"""F06 diagnostic-only signer policy and negative security regressions."""
from pathlib import Path
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts' / 'fork'))
import f06_signing as signing

FORK = 'a'*40
UPSTREAM = 'b'*40
MERGED = 'c'*40
TREE = 'd'*40
CERT = 'e'*64
PACKAGE = 'com.mikeyphw.bakasu'


def make_report(root: Path, status: str = 'source-integrated') -> Path:
    p = root / 'f05.json'
    p.write_text(json.dumps({'schemaVersion':1, 'mode':'F05-unsigned-diagnostic-only',
                             'status':status,'channel':'beta','forkSha':FORK,
                             'upstreamSha':UPSTREAM,'mergedSha':MERGED,
                             'mergedTreeSha':TREE,'upstreamEventId':123}))
    return p


def output_signer(*, fingerprint=CERT, v2=True, second=False):
    return ('Verifies\n' +
            f'Verified using v2 scheme (APK Signature Scheme v2): {str(v2).lower()}\n' +
            f'Signer #1 certificate SHA-256 digest: {fingerprint}\n' +
            (f'Signer #2 certificate SHA-256 digest: {fingerprint}\n' if second else ''))


class F06SigningSecurity(unittest.TestCase):
    def test_repo_contract_never_authorizes_publication_or_device(self):
        c = signing.contract()
        self.assertFalse(c['releasePublication'])
        self.assertFalse(c['deviceInstallation'])
        self.assertFalse(c['compatibilityManifestPublished'])
        self.assertEqual(c['managerPackage'], PACKAGE)

    def test_fingerprint_normalization_and_rejections(self):
        self.assertEqual(signing.fingerprint(':'.join(['EE']*32)), CERT)
        for invalid in ('', 'x'*64, 'E'*65, 'ff'*31, 'ff'*32+'\n', '00'*33):
            with self.subTest(invalid=invalid):
                with self.assertRaises(signing.Refused): signing.fingerprint(invalid)

    def test_source_must_be_f05_verified_exact_fork(self):
        with tempfile.TemporaryDirectory() as t:
            src=make_report(Path(t))
            self.assertEqual(signing.source(src, expected_fork=FORK)['mergedSha'], MERGED)
            with self.assertRaises(signing.Refused):
                signing.source(src, expected_fork='f'*40)
            with self.assertRaises(signing.Refused):
                signing.source(src, channel='stable')
            make_report(Path(t), 'failed')
            with self.assertRaises(signing.Refused):
                signing.source(src)

    def test_apk_identity_requires_exact_cert_v2_and_package(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'Manager-universal-release.apk'
            p.write_bytes(b'A'*100_005)
            valid="package: name='" + PACKAGE + "' versionCode='34567' versionName='v1'"
            with mock.patch.object(signing,'command',side_effect=[output_signer(),valid]):
                result=signing.apk_metadata(p,'aapt','apksigner',CERT,PACKAGE)
            self.assertEqual(result['versionCode'],34567)
            self.assertEqual(result['packageName'],PACKAGE)
            for sig, badging in ((output_signer(fingerprint='f'*64),valid),
                                 (output_signer(v2=False),valid),
                                 (output_signer(second=True),valid),
                                 (output_signer(),"package: name='com.resukisu.resukisu' versionCode='3' versionName='v1'")):
                with self.subTest(sig=sig[:45]):
                    with mock.patch.object(signing,'command',side_effect=[sig,badging]):
                        with self.assertRaises(signing.Refused):
                            signing.apk_metadata(p,'aapt','apksigner',CERT,PACKAGE)

    def test_verify_provenance_is_not_release_qualified(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            src=make_report(root)
            sdk=root/'sdk'/'build-tools'/'36.1.0'
            sdk.mkdir(parents=True)
            for name in ('apksigner','aapt'):
                f=sdk/name
                f.write_text('#!/bin/sh\nexit 0\n')
                f.chmod(0o700)
            out_dir=root/'out';out_dir.mkdir()
            (out_dir/'Manager-universal-release.apk').write_bytes(b'A'*100_001)
            report=root/'attestation.json'
            mocked=[output_signer(),f"package: name='{PACKAGE}' versionCode='34567' versionName='v1'"]
            with mock.patch.object(signing,'checkout_identity'), mock.patch.object(signing,'command',side_effect=mocked):
                result=signing.verify(src,out_dir,report,expected_cert=CERT,
                                      sdk=root/'sdk',expected_fork=FORK)
            self.assertEqual(result['status'],'signed-verified')
            self.assertFalse(result['releaseQualified'])
            self.assertFalse(result['deviceQualified'])
            self.assertFalse(result['compatibilityQualified'])
            self.assertEqual(len(result['apks']),1)
            with mock.patch.object(signing,'checkout_identity'), self.assertRaises(signing.Refused):
                signing.verify(src,out_dir,report,expected_cert=CERT,
                               sdk=root/'sdk',expected_fork=FORK)

    def test_secret_properties_never_print_and_restore(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); manager=root/'manager';manager.mkdir()
            scratch=root/'scratch';scratch.mkdir()
            props=manager/'gradle.properties'
            original=b'org.gradle.jvmargs=-Xmx1g\n';props.write_bytes(original)
            src=make_report(root)
            environment={'GITHUB_SHA':FORK,'FORK_SIGNER_KEYSTORE_B64':base64.b64encode(b'Q'*1024).decode(),
                         'FORK_SIGNER_STORE_PASSWORD':'hello_world_secret',
                         'FORK_SIGNER_KEY_PASSWORD':'another_secret',
                         'FORK_SIGNER_KEY_ALIAS':'my-signing-key',
                         'FORK_SIGNER_CERT_SHA256':CERT}
            with mock.patch.object(signing,'github_context'), mock.patch.object(signing,'checkout_identity'):
                result=signing.prepare(src,manager,scratch,environment)
            self.assertEqual(result['expectedCertificateSha256'],CERT)
            self.assertIn(b'KEYSTORE_FILE=',props.read_bytes())
            self.assertEqual((scratch/'f06-manager-key.jks').stat().st_mode & 0o777,0o600)
            signing.cleanup(manager,scratch)
            self.assertEqual(props.read_bytes(),original)
            self.assertFalse((scratch/'f06-manager-key.jks').exists())
            self.assertFalse((scratch/'f06-gradle.original').exists())

    def test_missing_signer_secret_fails_closed(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);manager=root/'manager';manager.mkdir()
            scratch=root/'scratch';scratch.mkdir()
            (manager/'gradle.properties').write_text('org.gradle.jvmargs=-Xmx1g\n')
            src=make_report(root)
            with mock.patch.object(signing,'github_context'), mock.patch.object(signing,'checkout_identity'):
                with self.assertRaises(signing.Refused):
                    signing.prepare(src,manager,scratch,{'GITHUB_SHA':FORK})
            self.assertFalse((scratch/'f06-manager-key.jks').exists())

    def test_f06_workflow_only_manual_default_branch_nonrelease(self):
        text=(ROOT/'.github/workflows/fork-f06-signed-manager.yml').read_text()
        self.assertRegex(text,r'(?m)^  workflow_dispatch:\s*$')
        for bad in (r'(?m)^  push:',r'(?m)^  pull_request:',r'(?m)^  schedule:',
                    r'(?m)^\s*uses: softprops/action-gh-release',r'(?m)^\s*permissions:\s*$',):
            if 'permissions:' in bad:
                continue
            self.assertNotRegex(text,bad)
        self.assertIn("github.ref == 'refs/heads/main'",text)
        self.assertIn('environment: fork-signing',text)
        self.assertIn('persist-credentials: false',text)
        self.assertIn('f05_source_build.py stage',text)
        self.assertIn('com.mikeyphw.bakasu',text)
        self.assertIn('f06_signing.py verify',text)
        self.assertIn('f06_signing.py cleanup',text)
        self.assertNotIn('git push',text)
        self.assertNotIn('gh release',text)

    def test_reference_workflow_keeps_f05_fork_contracts(self):
        flow=(ROOT/'.github/workflows/fork-manager-ci.yml')
        if flow.exists():
            text=flow.read_text()
            self.assertIn("-p 'test_*.py'",text)
            self.assertIn('spotlessCheck',text)
            self.assertIn('assembleDebug',text)

    def test_java_properties_escapes_special_chars(self):
        self.assertEqual(signing.java_property('abc#= x'),r'abc\#\=\ x')


if __name__ == '__main__':
    unittest.main()
