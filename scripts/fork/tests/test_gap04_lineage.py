"""GAP-04 behavioral controls: disposable Git/keystore and provider fixtures only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import release_lineage as lineage
import f06_signing as f06
import f07_release as f07
import gap04_fixtures as fixtures

CERT='9'*64


class RealSource(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.home=Path(tmp.name);self.repo=self.home/'repo';self.repo.mkdir()
        self.git('init','-b','main');self.git('config','user.name','Fixture');self.git('config','user.email','fixture@localhost')
        (self.repo/'config').mkdir();(self.repo/'manager').mkdir()
        (self.repo/'manager'/'gradle.properties').write_text('test=true\n')
        self.policy_path=self.repo/lineage.SIGNING_PATH
        self.policy_path.write_text(json.dumps({'schemaVersion':1}))
        self.commit('base');diagnostic=self.git('rev-parse','HEAD')
        (self.repo/'manager'/'gradle.properties').write_text('test=false\n')
        self.commit('promoted');source=self.git('rev-parse','HEAD');tree=self.git('rev-parse','HEAD^{tree}')
        self.row=fixtures.reservation(source,tree,diagnostic)
        self.policy=fixtures.policy(self.row,CERT);self.policy_path.write_text(json.dumps(self.policy));self.commit('reviewed')
        self.head=self.git('rev-parse','HEAD')
        self.env=dict(GITHUB_ACTIONS='true',GITHUB_REPOSITORY=lineage.REPO,GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_SHA=self.head,GITHUB_RUN_ID='310',GITHUB_RUN_ATTEMPT='1')
        self.remote=self.head
        self.run=dict(id=self.row['diagnosticRunId'],event='workflow_dispatch',head_branch='main',head_sha=diagnostic,head_repository={'full_name':lineage.REPO},status='completed',conclusion='success',run_attempt=1,path=lineage.F05_PATH,display_title=f"F05/beta/{self.row['upstreamSha']}/{diagnostic}/{self.row['diagnosticIntentId']}")
        self.artifact=dict(id=self.row['diagnosticArtifactId'],name=f"f05-promotion-{self.row['diagnosticRunId']}",digest='sha256:'+self.row['diagnosticArtifactSha256'],expired=False,workflow_run={'id':self.row['diagnosticRunId'],'head_sha':diagnostic},size_in_bytes=100)

    def git(self,*args):
        return subprocess.run(['git','-C',str(self.repo),*args],check=True,capture_output=True,text=True).stdout.strip()

    def commit(self,message):
        self.git('add','-A');self.git('commit','-m',message)

    def request(self,path):
        if path=='/git/ref/heads/main':return {'ref':'refs/heads/main','object':{'sha':self.remote}}
        if path==f"/actions/runs/{self.row['diagnosticRunId']}":return self.run
        if path==f"/actions/artifacts/{self.row['diagnosticArtifactId']}":return self.artifact
        if path=='/releases?per_page=100&page=1':return [{'id':1,'draft':False,'assets':[{'name':'BakaSU_v1_40004-riscv64-release.apk'}]}]
        raise AssertionError(path)

    def stage(self):
        with mock.patch.dict(os.environ,self.env):
            return f06.stage(self.row['reservationId'],self.row['versionCode'],self.head,self.home/'worktree',self.home/'stage.json',self.env,root=self.repo,client=self)

    def test_promoted_checkout_and_independent_release_identity(self):
        record=self.stage()
        self.assertEqual(record['reservation'],self.row)
        self.assertEqual((self.home/'worktree'/'manager'/'gradle.properties').read_text(),'test=false\n')
        self.assertEqual(lineage.git(self.home/'worktree','rev-parse','HEAD').decode().strip(),self.row['sourceCommit'])
        source=fixtures.signed(self.row,self.head,CERT)
        entry=fixtures.review(self.row,self.head,CERT)
        f07.source_identity(source,entry,root=self.repo,head=self.head)
        tampered=copy.deepcopy(source);tampered['source']['reservation']['sourceTree']='a'*40
        with self.assertRaises(f07.Refused):f07.source_identity(tampered,entry,root=self.repo,head=self.head)
        for key,val in [('run_attempt',2),('display_title','wrong')]:
            with self.subTest(key=key),self.assertRaises(f07.Refused):
                f07.run_identity(dict(fixtures.run_info(entry),**{key:val}),entry)

    def test_stage_stale_provider_metadata_and_expired_artifact(self):
        original=self.remote;self.remote='f'*40
        with self.assertRaisesRegex(f06.Refused,'REMOTE_MAIN_DRIFT'):self.stage()
        self.remote=original
        self.artifact['expired']=True
        with self.assertRaisesRegex(lineage.Refused,'ARTIFACT_MISMATCH'):self.stage()
        self.artifact['expired']=False;self.run['display_title']='unreviewed'
        with self.assertRaisesRegex(lineage.Refused,'EVENT_DRIFT'):self.stage()
        self.assertFalse((self.home/'worktree').exists())

    def test_signer_history_cannot_be_rewritten_by_review_rotation(self):
        lineage.signer_continuity(self.repo,self.head,CERT)
        self.policy['certificateSha256']='8'*64
        self.policy_path.write_text(json.dumps(self.policy));self.commit('attempted rotation')
        head=self.git('rev-parse','HEAD')
        with self.assertRaisesRegex(lineage.Refused,'ROTATION_REFUSED'):
            lineage.signer_continuity(self.repo,head,'8'*64)
        with self.assertRaises(f07.Refused):
            f07.source_identity(fixtures.signed(self.row,self.head,CERT),fixtures.review(self.row,self.head,CERT),root=self.repo,head=head)

    def test_registry_requires_unique_global_versions(self):
        row=fixtures.reservation(self.row['sourceCommit'],self.row['sourceTree'],self.row['diagnosticForkSha'])
        row.update(upstreamSha='7'*40,eventKey='beta:'+'7'*40,diagnosticRunId=99)
        row['reservationId']=lineage.digest({k:v for k,v in row.items() if k!='reservationId'})
        with self.assertRaisesRegex(lineage.Refused,'DUPLICATE_versionCode'):
            lineage.signing_policy(dict(self.policy,approvedReservations=[self.row,row]))

    def test_reviewed_reservation_history_cannot_drop_old_version(self):
        self.policy['approvedReservations']=[]
        self.policy_path.write_text(json.dumps(self.policy));self.commit('remove old reservation')
        with self.assertRaisesRegex(lineage.Refused,'HISTORICAL_RESERVATION'):
            lineage.signer_continuity(self.repo,self.git('rev-parse','HEAD'),CERT)

    def test_publication_registry_history_cannot_change_prior_review(self):
        entry=fixtures.review(self.row,self.head,CERT)
        path=self.repo/f07.REVIEW_PATH
        registry=dict(schemaVersion=2,repository=lineage.REPO,defaultBranch='main',approvedCandidates=[entry])
        path.write_text(json.dumps(registry));self.commit('publication review')
        f07.review_continuity(self.repo,self.git('rev-parse','HEAD'),registry)
        entry['managerUapi']=4;path.write_text(json.dumps(registry));self.commit('rewrite previous compatibility approval')
        with self.assertRaisesRegex(f07.Refused,'HISTORICAL_REVIEW'):
            f07.review_continuity(self.repo,self.git('rev-parse','HEAD'),registry)


class ArtifactArchive(unittest.TestCase):
    def test_raw_archive_digest_and_exact_flat_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/'artifact.zip';out=root/'out';out.mkdir()
            for names in [('f06-promoted-source.json','f06-signed-provenance.json'),
                          ('../f06-promoted-source.json','f06-signed-provenance.json'),
                          ('f06-promoted-source.json','unexpected.json')]:
                with zipfile.ZipFile(archive,'w') as z:
                    for name in names:z.writestr(name,'{}')
                if names[0]=='f06-promoted-source.json' and names[1]=='f06-signed-provenance.json':
                    with self.assertRaisesRegex(f07.Refused,'DIGEST_MISMATCH'):
                        f07.extract_f06_artifact(archive,out,'evidence','0'*64)
                    f07.extract_f06_artifact(archive,out,'evidence',f07.digest(archive))
                    self.assertEqual({x.name for x in out.iterdir()},set(names))
                    for path in out.iterdir():path.unlink()
                else:
                    with self.assertRaisesRegex(f07.Refused,'MEMBER_SET_INVALID'):
                        f07.extract_f06_artifact(archive,out,'evidence',f07.digest(archive))
                    self.assertFalse(list(out.iterdir()))
            with zipfile.ZipFile(archive,'w') as z:
                malicious=zipfile.ZipInfo('f06-promoted-source.json');malicious.external_attr=0o120777<<16
                z.writestr(malicious,'outside');z.writestr('f06-signed-provenance.json','{}')
            with self.assertRaisesRegex(f07.Refused,'MEMBER_UNSAFE'):
                f07.extract_f06_artifact(archive,out,'evidence',f07.digest(archive))
            self.assertFalse(list(out.iterdir()))

    def test_provider_attempt_archive_id_and_digest(self):
        entry=fixtures.review(fixtures.reservation(),'b'*40,CERT)
        def request(route):
            kind='evidence' if route.endswith(str(entry['evidenceArtifactId'])) else 'apk'
            return dict(id=entry[kind+'ArtifactId'],name=f07.artifact_name(entry,kind),digest='sha256:'+entry[kind+'ArtifactSha256'],expired=False,size_in_bytes=100,workflow_run={'id':entry['f06RunId'],'head_sha':entry['sourceForkSha']})
        self.assertEqual(set(f07.verify_f06_artifacts(entry,request)),{'evidence','apk'})
        for mutation in (dict(expired=True),dict(digest='sha256:'+'0'*64),dict(name='different-attempt'),dict(workflow_run={'id':999,'head_sha':entry['sourceForkSha']})):
            with self.subTest(mutation=mutation),self.assertRaises(f07.Refused):
                f07.verify_f06_artifacts(entry,lambda route:dict(request(route),**mutation))


class SignerAndAbi(unittest.TestCase):
    @unittest.skipUnless(shutil.which('keytool'),'JDK keytool unavailable; external qualification required')
    def test_real_keytool_checks_test_only_key_der(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'disposable.p12';env=dict(os.environ,TEST_STOREPASS='fixture-password-only')
            subprocess.run(['keytool','-genkeypair','-keystore',str(p),'-alias','fixture','-storetype','PKCS12','-keyalg','RSA','-keysize','2048','-validity','1','-dname','CN=Disposable Test Fixture','-storepass:env','TEST_STOREPASS','-keypass:env','TEST_STOREPASS'],env=env,check=True,capture_output=True,timeout=30)
            der=subprocess.run(['keytool','-exportcert','-keystore',str(p),'-alias','fixture','-storepass:env','TEST_STOREPASS'],env=env,check=True,capture_output=True,timeout=30).stdout
            cert=hashlib.sha256(der).hexdigest()
            f06.verify_keystore(p,'fixture',env['TEST_STOREPASS'],cert)
            with self.assertRaisesRegex(f06.Refused,'CERTIFICATE_MISMATCH'):
                f06.verify_keystore(p,'fixture',env['TEST_STOREPASS'],'0'*64)

    def test_riscv64_and_universal_native_badging(self):
        sig='Verified using v2 scheme (APK Signature Scheme v2): true\nSigner #1 certificate SHA-256 digest: '+CERT+'\n'
        with tempfile.TemporaryDirectory() as d:
            for abi,native in [('riscv64',['riscv64']),('universal',sorted(f06.NATIVE_ABIS))]:
                p=Path(d)/f'BakaSU_v1_40005-{abi}-release.apk';p.write_bytes(b'fixture'*15000)
                prefix="package: name='com.mikeyphw.bakasu' versionCode='40005' versionName='v1'\nnative-code: "
                with mock.patch.object(f06,'command',side_effect=[sig,prefix+' '.join(repr(x) for x in native)]):
                    self.assertEqual(f06.apk_metadata(p,'aapt','apksigner',CERT,f07.PACKAGE)['nativeAbis'],native)
                with mock.patch.object(f06,'command',side_effect=[sig,prefix+"'x86_64'"]),self.assertRaisesRegex(f06.Refused,'NATIVE_ABI_MISMATCH'):
                    f06.apk_metadata(p,'aapt','apksigner',CERT,f07.PACKAGE)


class PublicationRecovery(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.output=Path(tmp.name)
        for name in ('BakaSU_v1_40005-riscv64-release.apk','manager-compatibility.json','f07-release-provenance.json','f06-signed-provenance.json'):
            (self.output/name).write_bytes(name.encode())
        self.entry=fixtures.review(fixtures.reservation(),'b'*40,CERT)
        self.release=None;self.tag=None;self.mutations=[];self.ambiguous=False

    def rows(self):return [copy.deepcopy(self.release)] if self.release else []

    def add_asset(self,p):
        self.release['assets'].append(dict(id=len(self.release['assets'])+100,name=p.name,size=p.stat().st_size,digest='sha256:'+f07.digest(p),state='uploaded'))

    def api(self,route):
        self.assertEqual(route,f'repos/{f07.REPO}/releases/9');return copy.deepcopy(self.release)

    def command(self,args,**kwargs):
        self.mutations.append(args[2]);action=args[2]
        if action=='create':
            self.assertIsNone(self.release)
            self.release=dict(id=9,tag_name=self.entry['tag'],target_commitish=self.entry['sourceMergedSha'],prerelease=True,draft=True,body=f07.release_notes(self.entry),assets=[])
            for p in sorted(self.output.iterdir()):
                self.add_asset(p)
                if self.ambiguous:raise f07.Refused('uncertain creation')
        elif action=='upload':
            for path in args[4:args.index('-R')]:self.add_asset(Path(path))
        elif action=='edit':
            self.release.update(draft=False,published_at='fixture');self.tag={'type':'commit','sha':self.entry['sourceMergedSha']}
        else:raise AssertionError(args)
        return mock.Mock(returncode=0,stdout='',stderr='')

    def download(self,args,**kwargs):
        ident=int(args[2].rsplit('/',1)[-1]);asset=next(a for a in self.release['assets'] if a['id']==ident)
        kwargs['stdout'].write((self.output/asset['name']).read_bytes());return mock.Mock(returncode=0)

    def publish(self,resume=False):
        with (mock.patch.object(f07,'exact_remote_head'),mock.patch.object(f07,'release_inventory',side_effect=self.rows),
              mock.patch.object(f07,'fresh_run_guard'),mock.patch.object(f07,'read_tag',side_effect=lambda _:self.tag),
              mock.patch.object(f07,'api',side_effect=self.api),mock.patch.object(f07,'command',side_effect=self.command),
              mock.patch.object(f07.subprocess,'run',side_effect=self.download)):
            f07.publish(self.entry,self.output,head='b'*40,resume=resume)

    def test_ambiguous_create_resume_no_duplicate_or_overwrite(self):
        self.ambiguous=True
        with self.assertRaisesRegex(f07.Refused,'uncertain creation'):self.publish()
        with self.assertRaisesRegex(f07.Refused,'REQUIRES_RESUME'):self.publish()
        self.assertEqual(self.mutations,['create'])
        self.publish(resume=True);self.assertFalse(self.release['draft'])
        self.assertEqual(self.mutations,['create','upload','edit'])
        self.publish(resume=True);self.assertEqual(self.mutations,['create','upload','edit'])

    def test_resume_missing_or_wrong_transaction_fails_without_mutation(self):
        with self.assertRaisesRegex(f07.Refused,'NEVER_RECREATE'):self.publish(resume=True)
        self.ambiguous=True
        with self.assertRaises(f07.Refused):self.publish()
        self.release['body']='foreign'
        with self.assertRaisesRegex(f07.Refused,'IDENTITY_MISMATCH'):self.publish(resume=True)
        self.release['body']=f07.release_notes(self.entry);self.release['assets'][0]['digest']='sha256:'+'0'*64
        with self.assertRaisesRegex(f07.Refused,'ASSET_IDENTITY_MISMATCH'):self.publish(resume=True)
        self.assertEqual(self.mutations,['create'])
