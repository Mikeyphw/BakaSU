"""F07 publication eligibility and fail-closed promotion contracts."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'/'fork'))
import f07_release as f07
import release_lineage as lineage
import gap04_fixtures as fixtures

HEAD='a'*40
FORK_SHA='b'*40
CERT='c'*64
RUN=310
TAG='f07-v1.2.3-beta.1'
APKNAME='BakaSU_v1.2.3_40005-arm64-v8a-release.apk'


ROW=fixtures.reservation(HEAD,'d'*40,FORK_SHA)
POLICY=fixtures.policy(ROW,CERT)


def approved():
    return fixtures.review(ROW,FORK_SHA,CERT,RUN,tag=TAG)


def registry(items=None):
    return {'schemaVersion':2,'repository':f07.REPO,'defaultBranch':'main',
            'approvedCandidates':items if items is not None else [approved()]}


def signed():
    return fixtures.signed(ROW,FORK_SHA,CERT,RUN)


class ReleaseSecurityTests(unittest.TestCase):
    def test_current_review_registry_is_valid_and_all_entries_remain_explicit(self):
        # A hard-coded empty-only test becomes obsolete on the first reviewed
        # release. Validate the live registry, with no implicit approvals.
        doc=json.loads((ROOT/'config/fork-release-review.json').read_text())
        self.assertEqual(doc.get('schemaVersion'), 2)
        self.assertEqual(doc.get('repository'), f07.REPO)
        self.assertEqual(doc.get('defaultBranch'), 'main')
        rows=doc.get('approvedCandidates')
        self.assertIsInstance(rows, list)
        identities=set()
        for entry in rows:
            self.assertIsInstance(entry,dict)
            ident=(entry.get('f06RunId'), entry.get('tag'), entry.get('channel'))
            self.assertNotIn(ident,identities)
            identities.add(ident)
            self.assertEqual(f07.reviewed_entry(doc,*ident),entry)
        # A fresh unrelated identity is never authorized by any registry.
        with self.assertRaises(f07.Refused):
            f07.reviewed_entry(doc, 2147483647, 'f07-v9999999-beta', 'beta')

    def test_explicit_review_pin_requires_full_identity(self):
        self.assertEqual(f07.reviewed_entry(registry(),RUN,TAG,'beta')['sourceMergedSha'],HEAD)
        for mutation in ({'f06RunId':RUN+1},{'managerUapi':0},
                         {'certificateSha256':'f'*63},{'sourceMergedSha':'x'*40},
                         {'versionCode':True},{'minimumKernelSuVersion':None}):
            row=approved();row.update(mutation)
            with self.subTest(mutation=mutation),self.assertRaises(f07.Refused):
                f07.reviewed_entry(registry([row]),RUN,TAG,'beta')

    def test_duplicate_and_wrong_tag_or_channel_refused(self):
        with self.assertRaises(f07.Refused):f07.reviewed_entry(registry([approved(),approved()]),RUN,TAG,'beta')
        for tag,ch in [('v1.2.3','beta'),('f07-v1.2.3','beta'),(TAG,'stable'),('f07-v1.2.3-beta.1;rm','beta')]:
            with self.subTest(tag=tag),self.assertRaises(f07.Refused):
                f07.reviewed_entry(registry(),RUN,tag,ch)

    def test_only_successful_F06_fork_main_run(self):
        run=fixtures.run_info(approved())
        f07.run_identity(run,approved())
        for k,v in [('status','queued'),('event','pull_request'),('conclusion','failure'),
                    ('head_sha',HEAD),('path','.github/workflows/evil.yml'),('head_branch','feature/a')]:
            bad=dict(run);bad[k]=v
            with self.subTest(k=k),self.assertRaises(f07.Refused):f07.run_identity(bad,approved())

    def test_f06_evidence_must_match_committed_source_and_cert(self):
        with (mock.patch.object(lineage,'ancestor',return_value=True),
              mock.patch.object(lineage,'committed_source'),
              mock.patch.object(lineage,'signer_continuity'),
              mock.patch.object(lineage,'policy_at',return_value=POLICY)):
            f07.source_identity(signed(),approved(),head=HEAD)
            for key,value in [('certificateSha256','f'*64),('releaseQualified',True)]:
                changed=signed();changed[key]=value
                with self.subTest(key=key),self.assertRaises(f07.Refused):
                    f07.source_identity(changed,approved(),head=HEAD)
            with mock.patch.object(lineage,'committed_source',side_effect=lineage.Refused('tree drift')):
                with self.assertRaises(f07.Refused):f07.source_identity(signed(),approved(),head=HEAD)

    def test_absent_integrated_source_on_main_refused(self):
        with mock.patch.object(lineage,'ancestor',return_value=False), self.assertRaises(f07.Refused):
            f07.source_identity(signed(),approved(),head=HEAD)

    def test_signed_apk_inventory_and_abi(self):
        record=signed();payload=b'F07_TEST_BLOB'*10000
        record['apks']=[{'fileName':APKNAME,'sha256':hashlib.sha256(payload).hexdigest(),
                          'sizeBytes':len(payload),'packageName':f07.PACKAGE,'versionCode':40005,
                          'versionName':'v1.2.3','nativeAbis':['arm64-v8a'],'signerCertificateSha256':CERT}]
        self.assertEqual(f07.asset_names(record,approved()),{APKNAME})
        broken=json.loads(json.dumps(record));broken['apks'][0]['versionCode']=40004
        with self.assertRaises(f07.Refused):f07.asset_names(broken,approved())
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);apkdir=root/'apks';apkdir.mkdir();out=root/'out';out.mkdir()
            (apkdir/APKNAME).write_bytes(payload)
            metadata={**record['apks'][0]}
            with (mock.patch.object(f07,'sdk_tool',return_value=Path('/fake/tool')),
                  mock.patch.object(f07,'apk_metadata',return_value=metadata)):
                entry=fixtures.pin_signed(root/'signed.json',record,approved())
                report=f07.prepare_candidate(entry,record,apkdir,out,root,root/'signed.json')
            m=json.loads((out/'manager-compatibility.json').read_text())
            self.assertEqual(m['apks'][0]['managerUapi'],3)
            self.assertEqual(m['apks'][0]['minimumKernelSuVersion'],40000)
            self.assertFalse(report['releasePublished'])
            self.assertEqual(f07.digest(out/APKNAME),hashlib.sha256(payload).hexdigest())

    def test_signer_or_hash_tamper_refused(self):
        record=signed();payload=b'Z'*100500
        record['apks']=[{'fileName':APKNAME,'sha256':hashlib.sha256(payload).hexdigest(),
                          'sizeBytes':len(payload),'packageName':f07.PACKAGE,'versionCode':40005,
                          'versionName':'v1.2.3','nativeAbis':['arm64-v8a'],'signerCertificateSha256':CERT}]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'apks').mkdir();(root/'out').mkdir()
            (root/'apks'/APKNAME).write_bytes(b'Y'*len(payload))
            with (mock.patch.object(f07,'sdk_tool',return_value=Path('/fake/tool')),
                  mock.patch.object(f07,'apk_metadata',return_value=record['apks'][0])):
                with self.assertRaises(f07.Refused):
                    f07.prepare_candidate(approved(),record,root/'apks',root/'out',root,root/'signed.json')

    def test_version_code_history_monotonic(self):
        releases=[{'id':1,'tag_name':'prior','draft':False,'assets':[{'name':'BakaSU_old_40004-arm64-v8a-release.apk'}]},
                  {'id':2,'tag_name':'draft','draft':True,'assets':[{'name':'BakaSU_draft_90000-arm64-v8a-release.apk'}]}]
        with mock.patch.object(f07,'api',return_value=releases):
            f07.check_previous_versions(40005)
            with self.assertRaises(f07.Refused): f07.check_previous_versions(40004)

    def test_existing_release_tag_or_api_probe_error_refuses(self):
        with mock.patch.object(f07,'command',return_value=mock.Mock(returncode=0,stderr='',stdout=json.dumps({'ref':'refs/tags/'+TAG,'object':{'type':'commit','sha':HEAD}}))):
            with self.assertRaises(f07.Refused):f07.preflight_release_tag(TAG)
        with mock.patch.object(f07,'command',return_value=mock.Mock(returncode=1,stderr='HTTP 403 Forbidden')):
            with self.assertRaises(f07.Refused):f07.preflight_release_tag(TAG)

    def test_publisher_refuses_remote_main_drift_before_mutating(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)
            (out/'manager-compatibility.json').write_text('{}')
            (out/'f07-release-provenance.json').write_text('{}')
            (out/APKNAME).write_bytes(b'Z'*100000)
            with (mock.patch.object(f07,'git',return_value=HEAD),
                  mock.patch.object(f07,'api',return_value={'object':{'sha':FORK_SHA}}),
                  mock.patch.object(f07,'command') as cmd):
                with self.assertRaises(f07.Refused):f07.publish(approved(),out,head=HEAD)
                cmd.assert_not_called()

    def test_workflow_is_manual_protected_and_no_automatic_release(self):
        data=(ROOT/'.github/workflows/fork-f07-release.yml').read_text()
        self.assertIn('workflow_dispatch:',data)
        self.assertIn('environment: fork-release',data)
        self.assertIn('persist-credentials: false',data)
        for forbidden in ('  push:', '  pull_request:', '  schedule:', 'git push --force'):
            self.assertNotIn(forbidden,data)
        self.assertIn('--publish',data)

    def test_legacy_release_tag_trigger_must_be_avoided(self):
        legacy=(ROOT/'.github/workflows/release.yml')
        if legacy.exists():
            text=legacy.read_text()
            self.assertIn('- "v*"',text)
        self.assertFalse(TAG.startswith('v'))
        self.assertTrue(f07.TAG.fullmatch(TAG))
        self.assertFalse(f07.TAG.fullmatch('v1.2.3'))

if __name__=='__main__':unittest.main()
