"""Behavioral qualification: disposable Git, synthetic APKs, read-only provider/ADB fixtures."""
import copy
import concurrent.futures
import threading
import hashlib
import json
import os
import errno
from unittest import mock
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import acceptance_evidence as ev
import f09_device as device
import f10_reconcile as reconcile
import f08_qualification as f08
import f07_release as f07
import release_lineage as lineage
import event_journal as journal
import gap04_fixtures as fixtures
from test_f05_event_journal import candidate, seeded, run
ROOT=fixtures.ROOT
NOW=datetime(2026,11,27,12,tzinfo=timezone.utc)
CERT='9'*64
APK='BakaSU_v1.2.3_40005-arm64-v8a-release.apk'
SESSION='a'*64

def dump(path,value):path.write_text(json.dumps(value,sort_keys=True)+'\n')
def zip_members(path,files):
    with zipfile.ZipFile(path,'w') as z:
        for name,data in files.items():z.writestr(name,data)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

class Fixture:
    def __init__(self,home):
        self.home=home;self.repo=home/'repo';self.repo.mkdir();self.assets=home/'assets';self.assets.mkdir()
        self.git('init','-b','main');self.git('config','user.name','Fixture');self.git('config','user.email','fixture@localhost')
        self.git('remote','add','origin','https://github.com/'+ev.REPO+'.git')
        (self.repo/'config').mkdir();(self.repo/'source').write_text('base')
        self.policy_path=self.repo/lineage.SIGNING_PATH
        dump(self.policy_path,{'schemaVersion':1});self.registry_path=self.repo/f07.REVIEW_PATH
        self.registry=dict(schemaVersion=2,repository=ev.REPO,defaultBranch='main',approvedCandidates=[])
        dump(self.registry_path,self.registry)
        shutil.copyfile(ROOT/'config/delivery-required-ci.json',self.repo/'config/delivery-required-ci.json')
        self.commit('base');diagnostic=self.git('rev-parse','HEAD')
        (self.repo/'source').write_text('promoted');self.commit('promoted');source=self.git('rev-parse','HEAD');tree=self.git('rev-parse','HEAD^{tree}')
        state=seeded(candidate(source='e'*40));key='beta:'+'e'*40
        state,_=journal.begin(state,key,diagnostic);state=journal.observe(state,key,[run(state,key,ident=3101)])
        self.state,_=journal.reserve(state,key,dict(commit=source,tree=tree,diagnosticTree=tree,diagnosticRunId=3101,diagnosticArtifactId=3102,diagnosticArtifactSha256='2'*64),40004)
        self.row=lineage.export_reservation(self.state,key)
        self.policy=fixtures.policy(self.row,CERT);dump(self.policy_path,self.policy);self.commit('review signer');fork=self.git('rev-parse','HEAD')
        self.entry=fixtures.review(self.row,fork,CERT)
        self.apk=self.assets/APK;self.apk.write_bytes(b'synthetic apk bytes\n'*7000)
        self.signed=fixtures.signed(self.row,fork,CERT);self.metadata=dict(fileName=APK,sha256=sha(self.apk),sizeBytes=self.apk.stat().st_size,versionCode=40005,versionName='v1.2.3',packageName=f07.PACKAGE,nativeAbis=['arm64-v8a'],signerCertificateSha256=CERT)
        self.signed['apks']=[self.metadata];fixtures.pin_signed(self.assets/'f06-signed-provenance.json',self.signed,self.entry)
        self.ezip=home/'evidence.zip';self.azip=home/'apk.zip'
        zip_members(self.ezip,{'f06-promoted-source.json':json.dumps(self.signed['source']),'f06-signed-provenance.json':(self.assets/'f06-signed-provenance.json').read_bytes()})
        zip_members(self.azip,{APK:self.apk.read_bytes()})
        self.entry.update(evidenceArtifactSha256=sha(self.ezip),apkArtifactSha256=sha(self.azip))
        self.registry['approvedCandidates']=[self.entry];dump(self.registry_path,self.registry);self.commit('publication review');self.head=self.git('rev-parse','HEAD')
        self.provenance={k:self.entry[k] for k in ('tag','channel','f06RunId','f06RunAttempt','sourceMergedSha','sourceForkSha','sourceTree','reservationId','signedProvenanceSha256','certificateSha256')}
        self.provenance.update(schemaVersion=1,repository=ev.REPO,status='release-candidate-reviewed',releasePublished=False,reviewDigest=lineage.digest(self.entry),apks=[dict(name=APK,sha256=sha(self.apk),sizeBytes=self.apk.stat().st_size)])
        self.compat=dict(schemaVersion=1,apks=[dict(fileName=APK,versionCode=40005,abi='arm64-v8a',managerUapi=3,minimumKernelSuVersion=40000)])
        dump(self.assets/'f07-release-provenance.json',self.provenance);dump(self.assets/'manager-compatibility.json',self.compat)
        self.release=dict(id=110,tag_name=self.entry['tag'],draft=False,prerelease=True,target_commitish=source,published_at='2026-11-27T11:00:00Z',author={'login':'fixture'},body=f07.release_notes(self.entry),assets=[dict(id=500+i,name=p.name,size=p.stat().st_size,digest='sha256:'+sha(p)) for i,p in enumerate(sorted(self.assets.iterdir()))])
        self.tag=dict(ref='refs/tags/'+self.entry['tag'],object={'type':'commit','sha':source});self.f06run=fixtures.run_info(self.entry)
        self.ref=dict(tag=self.entry['tag'],runId=4001,runAttempt=1,artifactId=4002)
        self.auditrun=dict(id=4001,status='completed',conclusion='success',event='workflow_dispatch',head_branch='main',head_sha=self.head,head_repository={'full_name':ev.REPO},path=ev.F08_PATH,run_attempt=1,display_title='F08/'+self.entry['tag'])
        self.sdk=home/'sdk'/'build-tools'/'36.0.0';self.sdk.mkdir(parents=True)
        for tool in ('aapt','apksigner'):
            p=self.sdk/tool;p.write_text('#!/bin/sh\nexit 0\n');p.chmod(0o700)
        self.auditreport=self.check(self.entry['tag'],self.release,self.registry,self.provenance,self.f06run,self.compat,self.signed,self.assets,head=self.head,sdk=home/'sdk',tag_ref=self.tag,ancestor=lambda a,b:lineage.ancestor(self.repo,a,b),source_root=self.repo)
        self.auditreport['originalProviderArchiveDigestsVerified']=True
        f08.bind_audit_identity(self.auditreport,self.release,dict(GITHUB_RUN_ID='4001',GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='workflow_dispatch'))
        self.audit_zip=home/'audit.zip';self.refresh_audit()
        self.f06meta={kind:self.artifact(self.entry[kind+'ArtifactId'],f07.artifact_name(self.entry,kind),path,self.entry['f06RunId'],fork) for kind,path in [('apk',self.azip),('evidence',self.ezip)]}
    def git(self,*args):return subprocess.run(['git','-C',str(self.repo),*args],check=True,capture_output=True,text=True).stdout.strip()
    def commit(self,message):self.git('add','-A');self.git('commit','-m',message)
    def artifact(self,ident,name,path,run,head):return dict(id=ident,name=name,digest='sha256:'+sha(path),expired=False,size_in_bytes=path.stat().st_size,workflow_run=dict(id=run,head_sha=head))
    def refresh_audit(self):
        zip_members(self.audit_zip,{'qualification.json':json.dumps(self.auditreport)})
        self.auditmeta=self.artifact(4002,'fork-f08-published-release-audit-4001-1',self.audit_zip,4001,self.head)
    def get(self,path):
        table={'/actions/runs/4001':self.auditrun,'/actions/artifacts/4002':self.auditmeta,'/releases/tags/'+self.entry['tag']:self.release,'/git/ref/tags/'+self.entry['tag']:self.tag,'/git/ref/heads/main':dict(ref='refs/heads/main',object=dict(type='commit',sha=self.head)),'/actions/runs/'+str(self.entry['f06RunId']):self.f06run,'/releases?per_page=100&page=1':[self.release]}
        for row in self.f06meta.values():table['/actions/artifacts/'+str(row['id'])]=row
        if path.startswith('/actions/runs?head_sha='):
            required=json.loads((self.repo/'config/delivery-required-ci.json').read_text())['required_workflows']
            return dict(total_count=len(required),workflow_runs=[dict(id=i+10000,workflow_id=r['workflow_id'],name=r['name'],head_sha=self.head,head_branch='main',event='push',head_repository={'full_name':ev.REPO},run_attempt=1,status='completed',conclusion='success') for i,r in enumerate(required)])
        if path.startswith('/actions/workflows/'):return {'workflow_runs':[]}
        if path not in table:raise ValueError('fixture provider absent')
        return copy.deepcopy(table[path])
    def download(self,ident,dest,limit):
        p={4002:self.audit_zip,self.entry['apkArtifactId']:self.azip,self.entry['evidenceArtifactId']:self.ezip}[ident];assert p.stat().st_size<=limit;shutil.copyfile(p,dest)
    def asset(self,ident,dest):shutil.copyfile(self.assets/next(a['name'] for a in self.release['assets'] if a['id']==ident),dest)
    def check(self,*args,**kwargs):return f08.check_release(*args,**kwargs,apk_checker=lambda *a:self.metadata)
    def verify(self,ref=None,get=None):return ev.fetch_live_audit(ref or self.ref,self.registry,root=self.repo,head=self.head,get=get or self.get,download=self.download)

class FakeAdb:
    serial='fixture-device';boot='12345678-1234-1234-1234-123456789abc';remote='/data/app/~~token/com.mikeyphw.bakasu-token/base.apk'
    def __init__(self,path):self.apk=path;self.abis='arm64-v8a,armeabi-v7a';self.emulator='0';self.hash=sha(path)
    def run(self,*args,**kw):
        if args==('get-state',):return 'device'
        if args[-1]=='ro.product.cpu.abilist':return self.abis
        if args[-1]=='ro.build.version.sdk':return '35'
        if args[-1] in ('ro.kernel.qemu','ro.boot.qemu'):return self.emulator
        if args[:2]==('shell','sha256sum'):return self.hash+'  '+self.remote
        raise AssertionError(args)
    def path(self):return self.remote
    def size(self,path):return self.apk.stat().st_size
    def boot_id(self):return self.boot
    def pull(self,path,dest):shutil.copyfile(self.apk,dest)

class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.home=Path(tmp.name);self.f=Fixture(self.home)
    def test_live_audit_and_exact_git(self):
        f=self.f;self.assertEqual(ev.exact_main(f.repo,f.get),f.head);self.assertEqual(ev.committed_registry(f.repo,f.head),f.registry)
        report=f.verify();self.assertEqual(report['report']['githubAssets'],ev.live_assets(f.release));self.assertFalse(report['report']['deviceQualified'])
        (f.repo/'dirty').touch()
        with self.assertRaises(ev.Refused):ev.exact_main(f.repo,f.get)
    def test_provider_identity_and_raw_digest_refusals(self):
        f=self.f
        for obj,key,value in [(f.auditrun,'run_attempt',2),(f.auditrun,'head_sha','a'*40),(f.auditmeta,'expired',True),(f.auditmeta,'digest','sha256:'+'0'*64),(f.release,'id',999),(f.tag,'object',dict(type='commit',sha=f.head))]:
            prev=obj[key];obj[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):f.verify()
            obj[key]=prev
        f.auditreport['deviceQualified']=True;f.refresh_audit()
        with self.assertRaises(ev.Refused):f.verify()
    def test_provider_race(self):
        f=self.f;calls=0
        def get(path):
            nonlocal calls
            result=f.get(path)
            if path.startswith('/releases/tags/'):
                calls+=1
                if calls==2:result['id']+=1
            return result
        with self.assertRaisesRegex(ev.Refused,'CHANGED_DURING_READBACK'):f.verify(get=get)
    def test_archive_traversal_and_exclusive_output(self):
        p=self.home/'bad.zip';zip_members(p,{'../qualification.json':'{}'})
        with self.assertRaises(ev.Refused):ev.read_audit_zip(p,sha(p))
        path=self.home/'report.json';ev.write_private(path,{'a':1})
        with self.assertRaises(ev.Refused):ev.write_private(path,{'b':2})
        self.assertEqual(json.loads(path.read_bytes()),{'a':1});self.assertEqual(path.stat().st_mode&0o777,0o600)
    def test_missing_os_link_atomic_publication_and_collision(self):
        path=self.home/'termux.json'
        with mock.patch.object(os,'link',None,create=True):
            ev.write_private(path,{'first':1})
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads(path.read_bytes()),{'first':1})
            source=self.home/'candidate';source.write_bytes(b'candidate')
            with self.assertRaises(FileExistsError):ev.publish_noreplace(source,path)
            self.assertEqual(json.loads(path.read_bytes()),{'first':1})
            self.assertEqual(source.read_bytes(),b'candidate')
            target=self.home/'symlink';target.symlink_to(path)
            with self.assertRaises(FileExistsError):ev.publish_noreplace(source,target)
            self.assertTrue(target.is_symlink())
            self.assertEqual(list(self.home.glob('.audit-*')),[])
    def test_concurrent_no_link_writers_have_exactly_one_winner(self):
        path=self.home/'race.json';barrier=threading.Barrier(8)
        def writer(i):
            barrier.wait(timeout=10)
            try:
                ev.write_private(path,{'writer':i})
                return i
            except ev.Refused as error:
                self.assertIn('AUDIT_OUTPUT_ALREADY_EXISTS',str(error))
                return None
        with mock.patch.object(os,'link',None,create=True):
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                results=list(pool.map(writer,range(8)))
        winners=[i for i in results if i is not None]
        self.assertEqual(len(winners),1)
        self.assertEqual(json.loads(path.read_bytes()),{'writer':winners[0]})
        self.assertEqual(list(self.home.glob('.audit-*')),[])
    def test_unavailable_exclusive_publication_fails_closed(self):
        path=self.home/'unavailable.json'
        with mock.patch.object(os,'link',None,create=True), mock.patch('ctypes.CDLL',return_value=object()):
            with self.assertRaisesRegex(ev.Refused,'EXCLUSIVE_PUBLICATION_UNAVAILABLE'):ev.write_private(path,{'a':1})
        self.assertFalse(path.exists());self.assertEqual(list(self.home.glob('.audit-*')),[])
    def test_hard_link_unsupported_uses_atomic_fallback(self):
        path=self.home/'unsupported.json'
        with mock.patch.object(os,'link',side_effect=OSError(errno.EOPNOTSUPP,'unsupported'),create=True):
            ev.write_private(path,{'a':1})
        self.assertEqual(json.loads(path.read_bytes()),{'a':1})
    def test_device_capture_and_wrong_bytes(self):
        f=self.f;verified=f.verify();adb=FakeAdb(f.apk)
        capture=device.collect(verified,APK,'upgrade',SESSION,adb,owner_device=True,now=NOW)
        self.assertTrue(capture['installedBytesVerified']);self.assertFalse(capture['rootDaemonAuthorized']);self.assertNotIn(adb.serial,json.dumps(capture))
        for name,value in [('abis','x86'),('emulator','1'),('hash','0'*64)]:
            prev=getattr(adb,name);setattr(adb,name,value)
            with self.subTest(name=name),self.assertRaises(device.Refused):device.collect(verified,APK,'upgrade',SESSION,adb,owner_device=True)
            setattr(adb,name,prev)
        with self.assertRaises(device.Refused):device.collect(verified,APK,'upgrade',SESSION,adb,owner_device=False)
        f.apk.write_bytes(b'x'*f.apk.stat().st_size)
        with self.assertRaisesRegex(device.Refused,'BYTES_NOT_REVIEWED'):device.collect(verified,APK,'upgrade',SESSION,adb,owner_device=True)
    def test_device_session_and_manual_evidence(self):
        f=self.f;v=f.verify();old=copy.deepcopy(v);old['report']['tag']='f07-v1.2.2-beta.1';old['reference']=dict(v['reference'],tag=old['report']['tag']);old['releaseId']=99
        old['report']['reservationId']='0'*64;oldapk=APK.replace('40005','40004');old['report']['apks'][0].update(fileName=oldapk,versionCode=40004);old['report']['githubAssets'][oldapk]=old['report']['githubAssets'].pop(APK)
        adb=FakeAdb(f.apk);records=[]
        for i,stage in enumerate(device.STAGES):
            version=old if stage in ('baseline','rollback') else v
            if stage=='reboot':adb.boot='12345678-1234-1234-1234-123456789abd'
            records.append(device.collect(version,oldapk if version is old else APK,stage,SESSION,adb,owner_device=True,now=NOW+timedelta(minutes=i)))
        cases=[]
        for i,(ident,stage) in enumerate(device.CASES.items()):
            p=self.home/f'case{i}.txt';p.write_text(f'synthetic evidence {i}');cases.append(dict(id=ident,stage=stage,result='PASS',observation='fixture only',evidence=[dict(file=p.name,sha256=sha(p))]))
        manual=dict(schemaVersion=1,session=SESSION,cases=cases);lookup={x['report']['tag']:x for x in (old,v)}
        result=device.review_session(records,manual,lookup,self.home)
        self.assertEqual(result['status'],'DEVICE_EVIDENCE_REVIEW_REQUIRED');self.assertFalse(result['deviceQualified'])
        records[2]['bootId']=records[1]['bootId'];self.assertEqual(device.review_session(records,manual,lookup,self.home)['status'],'DEVICE_EVIDENCE_INCOMPLETE_OR_FAILED')
        cases[-1]['evidence']=cases[0]['evidence']
        with self.assertRaisesRegex(device.Refused,'EVIDENCE_REUSED'):device.review_session(records,manual,lookup,self.home)
    def test_journal_and_final_audit(self):
        f=self.f;self.assertEqual(reconcile.validate_journal(f.state,f.policy,f.registry)['approvedCount'],1)
        result=reconcile.audit(f.repo,f.head,f.registry,f.policy,f.state,[f.ref],get=f.get,fetch=lambda ref,*a,**k:f.verify(ref))
        self.assertEqual(len(result['milestones']),10);self.assertEqual(result['fullyAcceptedCount'],0);self.assertEqual(result['releaseAudit']['liveF08Count'],1);self.assertTrue(all(x['status']=='PASS' for x in result['requiredCi']))
        f.tag['object']['sha']='0'*40
        with self.assertRaisesRegex(reconcile.Refused,'TAG_DRIFT'):reconcile.audit(f.repo,f.head,f.registry,f.policy,f.state,[],get=f.get)
        with self.assertRaises(reconcile.Refused):reconcile.validate_journal(seeded(),f.policy,f.registry)
    def test_retention_and_offline_replay(self):
        f=self.f;folder=self.home/'retained'
        result=reconcile.retain_bundle(folder,f.ref,f.registry,root=f.repo,head=f.head,sdk=f.home/'sdk',get=f.get,download=f.download,asset_download=f.asset,checker=f.check)
        self.assertEqual(result['status'],'RETAINED_RELEASE_ARCHIVE_VERIFIED');self.assertFalse(result['freshProviderQualification'])
        report=reconcile.replay_bundle(folder,f.registry,root=f.repo,head=f.head,sdk=f.home/'sdk',checker=f.check)
        self.assertEqual(report['tag'],f.entry['tag']);self.assertFalse(report['deviceQualified'])
        with self.assertRaises(FileExistsError):reconcile.retain_bundle(folder,f.ref,f.registry,root=f.repo,head=f.head,sdk=f.home/'sdk',get=f.get,download=f.download,asset_download=f.asset,checker=f.check)
        (folder/'assets'/APK).write_bytes(b'tamper')
        with self.assertRaisesRegex(reconcile.Refused,'MANIFEST_DRIFT'):reconcile.replay_bundle(folder,f.registry,root=f.repo,head=f.head,sdk=f.home/'sdk',checker=f.check)
    def test_signer_review_actual_der_and_source(self):
        f=self.f;repo=self.home/'signer';repo.mkdir()
        def git(*args):return subprocess.run(['git','-C',str(repo),*args],check=True,capture_output=True,text=True).stdout.strip()
        git('init','-b','main');git('config','user.name','Fixture');git('config','user.email','fixture@localhost')
        cert=self.home/'public.der';key=self.home/'private-test-key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=Fixture','-days','1','-keyout',str(key),'-outform','DER','-out',str(cert)],check=True,capture_output=True)
        for path in ('kernel/manager/manager_sign.h','kernel/manager/apk_sign.c','kernel/feature/dynamic_manager.c','kernel/supercall/dispatch.c','kernel/Kbuild','userspace/ksud/src/android/dynamic_manager.rs'):
            dst=repo/path;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/path,dst)
        p=repo/lineage.SIGNING_PATH;p.parent.mkdir();dump(p,dict(f.policy,certificateSha256=sha(cert),approvedReservations=[]));git('add','-A');git('commit','-m','fixture signer review');head=git('rev-parse','HEAD')
        out=device.signer_review(repo,head,cert);self.assertTrue(out['dynamicManagerRootPermissionSourcePresent']);self.assertFalse(out['defaultBakaSUStaticKeyMatches']);self.assertFalse(out['rootDaemonAuthorized'])
        cert.write_bytes(cert.read_bytes()+b'x')
        with self.assertRaises(device.Refused):device.signer_review(repo,head,cert)
    def test_inventory_duplicate_and_missing_page_refuse(self):
        f=self.f
        with self.assertRaisesRegex(reconcile.Refused,'AMBIGUOUS'):reconcile.inventory(lambda p:[f.release,f.release])
        with self.assertRaisesRegex(reconcile.Refused,'CI_RUN_LIST_INCOMPLETE'):reconcile.hosted_required(f.repo,f.head,lambda p:{'total_count':1,'workflow_runs':[]})
    def test_retention_failed_download_removes_only_new_folder(self):
        f=self.f;out=self.home/'retained';marker=self.home/'marker';marker.write_text('preserve')
        def bad(ident,dest):dest.write_bytes(b'bad')
        with self.assertRaises(ValueError):reconcile.retain_bundle(out,f.ref,f.registry,root=f.repo,head=f.head,sdk=f.home/'sdk',get=f.get,download=f.download,asset_download=bad,checker=f.check)
        self.assertFalse(out.exists());self.assertEqual(marker.read_text(),'preserve')
    def test_unknown_published_release_refused(self):
        f=self.f;release=dict(f.release,tag_name='unreviewed',id=123)
        with self.assertRaisesRegex(reconcile.Refused,'UNREVIEWED'):reconcile.reconcile_releases(f.registry,[release],{})

if __name__=='__main__':unittest.main()
