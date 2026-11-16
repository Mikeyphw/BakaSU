"""F08 independent published-release qualification: positive and adversarial cases."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'scripts'/'fork'))
import f08_qualification as f08

HEAD = 'a' * 40
FORK = 'b' * 40
CERT = 'c' * 64
RUN = 310
TAG = 'f07-v1.2.3-beta.1'
APK = 'BakaSU_v1.2.3_40005-arm64-v8a-release.apk'
PACKAGE = 'com.mikeyphw.bakasu'


def reviewed():
    return {'f06RunId':RUN, 'tag':TAG, 'channel':'beta', 'sourceMergedSha':HEAD,
            'sourceForkSha':FORK, 'certificateSha256':CERT, 'managerUapi':3,
            'minimumKernelSuVersion':40000, 'versionCode':40005}


class Fixture:
    def __init__(self, directory: str):
        self.root = Path(directory)
        self.assets = self.root/'assets'
        self.assets.mkdir()
        self.apk_data = b'F08-synthetic-binary-not-a-real-APK' * 3700
        self.sha = hashlib.sha256(self.apk_data).hexdigest()
        (self.assets/APK).write_bytes(self.apk_data)
        self.registry = {'schemaVersion':1,'repository':f08.REPO,'defaultBranch':'main',
                         'approvedCandidates':[reviewed()]}
        self.provenance = {'schemaVersion':1,'repository':f08.REPO,'status':'release-candidate-reviewed',
                           'releasePublished':False,'tag':TAG,'channel':'beta','f06RunId':RUN,
                           'sourceMergedSha':HEAD,'sourceForkSha':FORK,'certificateSha256':CERT,
                           'apks':[{'name':APK,'sha256':self.sha,'sizeBytes':len(self.apk_data)}]}
        self.compat = {'schemaVersion':1,'apks':[{'fileName':APK,'versionCode':40005,
                    'abi':'arm64-v8a','managerUapi':3,'minimumKernelSuVersion':40000}]}
        self.f06 = {'schemaVersion':1,'repository':f08.REPO,
                    'mode':'F06-signed-artifact-not-a-release','status':'signed-verified',
                    'releaseQualified':False,'deviceQualified':False,'compatibilityQualified':False,
                    'certificateSha256':CERT,
                    'source':{'mergedSha':HEAD,'forkSha':FORK,'channel':'beta',
                              'mergedTreeSha':'d'*40,'upstreamSha':'e'*40,'upstreamEventId':19},
                    'apks':[{'fileName':APK,'sha256':self.sha,'sizeBytes':len(self.apk_data),
                             'signerCertificateSha256':CERT,'packageName':PACKAGE,
                             'versionCode':40005,'versionName':'v1.2.3'}]}
        self.run = {'id':RUN,'event':'workflow_dispatch','status':'completed','conclusion':'success',
                    'head_branch':'main','head_sha':FORK,
                    'head_repository':{'full_name':f08.REPO},'run_attempt':1,'path':f08.RUN_PATH}
        self.release = {'tag_name':TAG,'draft':False,'prerelease':True,
                        'published_at':'2026-11-16T20:00:00Z',
                        'target_commitish':HEAD,'author':{'login':'operator'},
                        'assets':[]}
        self.sync()
        self.sdk = self.root/'sdk'/'build-tools'/'36.0.0'
        self.sdk.mkdir(parents=True)
        for tool in ('aapt','apksigner'):
            path=self.sdk/tool;path.write_bytes(b'#!/bin/sh\nexit 0\n');path.chmod(0o700)

    def sync(self):
        for name, row in (('f07-release-provenance.json',self.provenance),
                          ('manager-compatibility.json',self.compat)):
            (self.assets/name).write_text(json.dumps(row)+'\n',encoding='utf-8')
        self.release['assets']=[{'name':p.name,'size':p.stat().st_size} for p in self.assets.iterdir()]

    def audit(self, *, checker=None, ancestor=None):
        row={'fileName':APK,'sha256':self.sha,'sizeBytes':len(self.apk_data),
             'versionCode':40005,'versionName':'v1.2.3','packageName':PACKAGE,
             'signerCertificateSha256':CERT}
        return f08.check_release(TAG,self.release,self.registry,self.provenance,self.run,
                self.compat,self.f06,self.assets,head=HEAD,sdk=self.root/'sdk',
                ancestor=ancestor or (lambda merged,main: merged == HEAD and main == HEAD),
                apk_checker=checker or (lambda *args: row))


class PublishedReleaseAuditTests(unittest.TestCase):
    def with_fixture(self, check):
        with tempfile.TemporaryDirectory() as d:
            check(Fixture(d))

    def test_valid_signed_report_is_not_device_authorization(self):
        def check(f):
            result=f.audit()
            self.assertEqual(result['status'],'f08-published-artifacts-verified')
            self.assertEqual(result['apks'][0]['sha256'],f.sha)
            self.assertTrue(result['signedApksReverified'])
            self.assertFalse(result['deviceQualified'])
            self.assertFalse(result['rootDaemonAuthorized'])
            self.assertFalse(result['releaseBuildPerformed'])
        self.with_fixture(check)

    def test_unreviewed_release_is_refused(self):
        def check(f):
            f.registry['approvedCandidates']=[]
            with self.assertRaises(f08.Refused):f.audit()
        self.with_fixture(check)

    def test_incorrect_f06_run_provenance_refused(self):
        def check(f):
            for key,value in [('id',RUN+1),('head_sha',HEAD),('head_branch','dev'),
                              ('event','pull_request'),('conclusion','failure'),
                              ('status','in_progress'),('path','.github/workflows/forged.yml'),
                              ('run_attempt',0)]:
                orig=f.run[key];f.run[key]=value
                with self.subTest(key=key),self.assertRaises(f08.Refused):f.audit()
                f.run[key]=orig
        self.with_fixture(check)

    def test_original_f06_artifact_evidence_is_required_and_matched(self):
        def check(f):
            for target,value in [('certificateSha256','f'*64),('releaseQualified',True),
                                 ('status','failed')]:
                orig=f.f06[target];f.f06[target]=value
                with self.subTest(target=target),self.assertRaises(f08.Refused):f.audit()
                f.f06[target]=orig
            f.f06['apks'][0]['sha256']='f'*64
            with self.assertRaises(f08.Refused):f.audit()
        self.with_fixture(check)

    def test_release_identity_and_state_fail_closed(self):
        def check(f):
            for key,value in [('draft',True),('prerelease',False),('target_commitish',FORK),
                              ('published_at',''),('tag_name','f07-vwrong'),('assets',[])]:
                orig=f.release[key];f.release[key]=value
                with self.subTest(key=key),self.assertRaises(f08.Refused):f.audit()
                f.release[key]=orig
        self.with_fixture(check)

    def test_source_ancestor_and_signer_pin_refused(self):
        def check(f):
            with self.assertRaises(f08.Refused):f.audit(ancestor=lambda *a:False)
            f.registry['approvedCandidates'][0]['certificateSha256']='d'*64
            with self.assertRaises(f08.Refused):f.audit()
        self.with_fixture(check)

    def test_apk_hash_size_and_reverification_refused(self):
        def check(f):
            (f.assets/APK).write_bytes(b'Z'*len(f.apk_data))
            with self.assertRaises(f08.Refused):f.audit()
            (f.assets/APK).write_bytes(f.apk_data)
            for field,value in [('packageName','org.other.app'),('versionCode',40004),
                                ('signerCertificateSha256','f'*64),('sha256','f'*64)]:
                valid={'fileName':APK,'sha256':f.sha,'sizeBytes':len(f.apk_data),
                        'versionCode':40005,'versionName':'v1.2.3',
                        'packageName':PACKAGE,'signerCertificateSha256':CERT}
                valid[field]=value
                with self.subTest(field=field),self.assertRaises(f08.Refused):
                    f.audit(checker=lambda *a:valid)
        self.with_fixture(check)

    def test_unreviewed_compatibility_and_duplicate_abi_refused(self):
        def check(f):
            for field,value in [('managerUapi',5),('minimumKernelSuVersion',40001),
                                ('abi','x86_64'),('versionCode',40004)]:
                orig=f.compat['apks'][0][field];f.compat['apks'][0][field]=value
                with self.subTest(field=field),self.assertRaises(f08.Refused):f.audit()
                f.compat['apks'][0][field]=orig
            f.compat['apks'].append(copy.deepcopy(f.compat['apks'][0]))
            with self.assertRaises(f08.Refused):f.audit()
        self.with_fixture(check)

    def test_extra_asset_symlink_and_github_size_refused(self):
        def check(f):
            (f.assets/'unexpected.txt').write_text('tampered')
            with self.assertRaises(f08.Refused):f.audit()
            (f.assets/'unexpected.txt').unlink()
            (f.assets/'evil').symlink_to(f.assets/APK)
            with self.assertRaises(f08.Refused):f.audit()
            (f.assets/'evil').unlink()
            f.release['assets'][0]['size']+=1
            with self.assertRaises(f08.Refused):f.audit()
        self.with_fixture(check)

    def test_readonly_workflow_has_strict_no_publish_no_secrets(self):
        script=(ROOT/'.github/workflows/fork-f08-release-qualification.yml').read_text()
        self.assertIn('workflow_dispatch:',script)
        self.assertIn("github.ref == 'refs/heads/main'",script)
        self.assertIn('persist-credentials: false',script)
        self.assertIn('contents: read',script)
        self.assertIn('actions: read',script)
        self.assertIn('f08_qualification.py',script)
        for forbidden in ('  pull_request:', '  push:', '  schedule:',
                          'contents: write','gh release create','gh release edit',
                          'gh release upload', 'secrets.FORK_SIGNER_KEYSTORE_B64',
                          'ksud module install','adb install'):
            self.assertNotIn(forbidden,script)

    def test_malformed_or_oversized_json_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'data.json';p.write_text('{bad}')
            with self.assertRaises(f08.Refused):f08.read_json_file(p)
            p.write_text('{}')
            self.assertEqual(f08.read_json_file(p),{})
            with self.assertRaises(f08.Refused):f08.read_json_file(p,max_bytes=1)
            p.unlink();p.symlink_to('/dev/null')
            with self.assertRaises(f08.Refused):f08.read_json_file(p)


if __name__=='__main__':unittest.main()
