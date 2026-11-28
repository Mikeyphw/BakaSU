#!/usr/bin/env python3
"""Read-only reviewed promotion evidence. No source, release or signing mutation.

A hosted diagnostic merge is not itself a persistent main commit. Verify the
actual integrated Git tree, then prepare a review inventory for native delivery.
Reserve a version only when the corresponding tree is independently observed in
an actual committed ancestor of canonical main.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path, PurePosixPath
import re
import subprocess

from event_journal import require,sha,integer,MAX_VERSION,REPO

MAX_PATHS=48
MAX_BATCHES=4
MAX_RELEASE_PAGES=20
APK=re.compile(r'BakaSU_(.+)_([1-9][0-9]{0,9})-(arm64-v8a|armeabi-v7a|x86_64|riscv64|universal)-release\.apk\Z')
HEX256=re.compile(r'^[0-9a-f]{64}$')


def git(root: Path,*args: str)->bytes:
    proc=subprocess.run(['git','--no-replace-objects','-C',str(root),*args],capture_output=True,check=False,timeout=45)
    require(proc.returncode==0,'PROMOTION_GIT_REFUSED_'+args[0]);return proc.stdout


def oid(root: Path,spec: str)->str:
    value=git(root,'rev-parse','--verify',spec).decode().strip();require(sha(value),'PROMOTION_GIT_IDENTITY_INVALID');return value


def ancestor(root: Path,commit: str,head: str)->bool:
    p=subprocess.run(['git','--no-replace-objects','-C',str(root),'merge-base','--is-ancestor',commit,head],capture_output=True,timeout=45)
    require(p.returncode in (0,1),'PROMOTION_ANCESTRY_UNAVAILABLE');return p.returncode==0


def verify_diagnostic(root: Path,row: dict,report: dict)->dict:
    e=row['event'];attempts=row['attempts'];require(attempts and attempts[-1]['state']=='qualified','PROMOTION_DIAGNOSTIC_NOT_SUCCESSFUL');a=attempts[-1]
    require(isinstance(report,dict) and report.get('schemaVersion')==1 and report.get('mode')=='F05-unsigned-diagnostic-only' and report.get('status')=='debug-build-validated','PROMOTION_REPORT_INVALID')
    require(report.get('channel')==e['channel'] and report.get('upstreamSha')==e['source'] and report.get('upstreamEventId')==e['eventId'] and report.get('forkSha')==a['forkSha'],'PROMOTION_REPORT_EVENT_MISMATCH')
    merged,tree=report.get('mergedSha'),report.get('mergedTreeSha');require(sha(merged) and sha(tree),'PROMOTION_REPORT_TREE_INVALID')
    checksums=report.get('apkChecksums');require(isinstance(checksums,dict) and 1<=len(checksums)<=12 and all(isinstance(k,str) and k.endswith('.apk') and PurePosixPath(k).name==k and isinstance(v,str) and HEX256.fullmatch(v) for k,v in checksums.items()),'PROMOTION_BUILD_ARTIFACTS_MISSING')
    require(oid(root,merged+'^{commit}')==merged and oid(root,merged+'^{tree}')==tree,'PROMOTION_TREE_MISMATCH')
    if report.get('integrationMode')=='merge-commit':
        parents=git(root,'rev-list','--parents','-n','1',merged).decode().split()
        require(parents==[merged,a['forkSha'],e['source']],'PROMOTION_MERGE_PARENTS_MISMATCH')
    else:
        require(report.get('integrationMode')=='already-ancestor' and merged==a['forkSha'] and ancestor(root,e['source'],merged),'PROMOTION_ANCESTRY_MISMATCH')
    return {'commit':merged,'tree':tree,'forkSha':a['forkSha'],'diagnosticRunId':a['runId'],'upstreamSha':e['source']}


def _batch_trees(root: Path, base: str, entries: list[dict], final_tree: str) -> list[dict]:
    """Reconstruct exact trees with a disposable index, never the owner index/ref.

    Deletions precede additions so file/directory transitions remain representable.
    Every intermediate tree is independently bound to the ordered inventory.
    No worktree files, branch refs or provider state are modified here.
    """
    require(len(entries)<=MAX_PATHS*MAX_BATCHES,'PROMOTION_BATCH_CAP_REVIEW_REQUIRED')
    ordered=sorted(entries,key=lambda e:(e['action']!='delete',e['path']))
    require(len({e['path'] for e in ordered})==len(ordered),'PROMOTION_DUPLICATE_PATH')
    batches=[]
    with tempfile.TemporaryDirectory(prefix='bakasu-promotion-index-') as folder:
        env={k:v for k,v in os.environ.items() if k not in ('GIT_INDEX_FILE','GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES')}
        env.update(GIT_INDEX_FILE=str(Path(folder)/'index'),GIT_NO_REPLACE_OBJECTS='1')
        def index_git(*args, data=None):
            proc=subprocess.run(['git','--no-replace-objects','-C',str(root),*args],input=data,env=env,capture_output=True,timeout=45,check=False)
            require(proc.returncode==0,'PROMOTION_INDEX_REFUSED_'+args[0]);return proc.stdout
        index_git('read-tree',base)
        before=index_git('write-tree').decode().strip()
        require(before==oid(root,base+'^{tree}'),'PROMOTION_INDEX_BASE_TREE_MISMATCH')
        for offset in range(0,len(ordered),MAX_PATHS):
            chunk=ordered[offset:offset+MAX_PATHS]
            data=b''.join((e['new_mode']+' '+e['new_blob']+'\t'+e['path']).encode('utf-8')+b'\0' for e in chunk)
            index_git('update-index','-z','--index-info',data=data)
            after=index_git('write-tree').decode().strip();require(sha(after),'PROMOTION_BATCH_TREE_INVALID')
            batches.append({'number':len(batches)+1,'base_tree':before,'post_tree':after,'paths':[e['path'] for e in chunk]})
            before=after
        require(before==final_tree,'PROMOTION_BATCH_FINAL_TREE_MISMATCH')
    return batches


def inventory(root: Path,row: dict,report: dict,main: str)->dict:
    proof=verify_diagnostic(root,row,report);require(main==proof['forkSha'],'PROMOTION_MAIN_DRIFT_REQUALIFY')
    # Each batch remains bounded by the native 48-path limit. A larger or
    # unsupported mode inventory still refuses rather than approximating it.
    raw=git(root,'diff','--raw','--no-abbrev','--no-renames','-z',main,proof['commit']).split(b'\0')
    require(raw[-1]==b'' and (len(raw)-1)%2==0,'PROMOTION_DIFF_INVALID')
    entries=[]
    for meta,name in zip(raw[:-1:2],raw[1:-1:2]):
        fields=meta.decode('ascii').lstrip(':').split();require(len(fields)==5,'PROMOTION_DIFF_INVALID')
        oldmode,newmode,oldoid,newoid,status=fields
        path=name.decode('utf-8','strict');parts=PurePosixPath(path).parts
        require(parts and not path.startswith('/') and '\\' not in path and ':' not in path and all(p not in ('','.','..','.git','.devtool-artifact.json') for p in path.split('/')) and not any(ord(c)<32 or ord(c)==127 for c in path),'PROMOTION_PATH_UNSAFE')
        require(status in ('A','D','M') and ((oldmode,newmode) in (('000000','100644'),('100644','000000'),('100644','100644')) or (status=='M' and oldmode==newmode=='100755')),'PROMOTION_MODE_REQUIRES_REVIEW')
        require(sha(oldoid) and sha(newoid),'PROMOTION_BLOB_IDENTITY_INVALID')
        before=None if status=='A' else hashlib.sha256(git(root,'cat-file','blob',oldoid)).hexdigest()
        post_bytes=None if status=='D' else git(root,'cat-file','blob',newoid)
        after=None if post_bytes is None else hashlib.sha256(post_bytes).hexdigest()
        entries.append({'path':path,'action':{'A':'add','D':'delete','M':'modify'}[status],'source_sha256':before,'sha256':after,'size':len(post_bytes or b''),'old_blob':oldoid,'new_blob':newoid,'old_mode':oldmode,'new_mode':newmode})
    require(len(entries)<=MAX_PATHS*MAX_BATCHES,'PROMOTION_BATCH_CAP_REVIEW_REQUIRED')
    reported=report.get('changedPaths');require(isinstance(reported,list) and all(isinstance(p,str) for p in reported) and len(reported)==len(set(reported)),'PROMOTION_REPORT_INVENTORY_INVALID')
    # Earlier schema-1 producers used Git's rename-aware name-only output.
    # Reconcile that exact historical projection as well as the current
    # complete add/delete projection; neither can drop a path in the plan.
    legacy=git(root,'diff','--name-only','-z','--find-renames',main,proof['commit']).split(b'\0')
    require(legacy[-1]==b'','PROMOTION_LEGACY_DIFF_INVALID')
    require(set(reported) in ({x['path'] for x in entries},{p.decode('utf-8','strict') for p in legacy[:-1]}),'PROMOTION_REPORT_INVENTORY_MISMATCH')
    batches=_batch_trees(root,main,entries,proof['tree'])
    return {'schemaVersion':2,'repository':REPO,'status':'REVIEW_REQUIRED','base_commit':main,'base_tree':oid(root,main+'^{tree}'),'post_tree':proof['tree'],'diagnostic_commit':proof['commit'],'diagnostic_run':proof['diagnosticRunId'],'upstream_sha':proof['upstreamSha'],'entries':entries,'batches':batches,'max_paths_per_batch':MAX_PATHS}


def promoted(root: Path,row: dict,report: dict,commit: str,main: str)->dict:
    proof=verify_diagnostic(root,row,report)
    require(sha(commit) and sha(main) and ancestor(root,commit,main),'PROMOTED_COMMIT_NOT_MAIN_ANCESTOR')
    require(ancestor(root,proof['forkSha'],commit) and oid(root,commit+'^{tree}')==proof['tree'],'PROMOTED_SOURCE_TREE_MISMATCH')
    return {'commit':commit,'tree':proof['tree'],'diagnosticRunId':proof['diagnosticRunId'],'diagnosticTree':proof['tree']}


def published_version_floor(client)->int:
    """Read the complete relevant release listing; fail on ambiguous assets."""
    highest=0;seen=set()
    for page in range(1,MAX_RELEASE_PAGES+1):
        releases=client.request(f'/releases?per_page=100&page={page}')
        require(isinstance(releases,list) and len(releases)<=100,'VERSION_RELEASE_PAGE_INVALID')
        for release in releases:
            rid=release.get('id');require(integer(rid,1,2**63-1) and rid not in seen,'VERSION_RELEASE_PAGINATION_AMBIGUOUS');seen.add(rid)
            require(type(release.get('draft')) is bool,'VERSION_RELEASE_SCHEMA_INVALID')
            if release['draft']:continue
            assets=release.get('assets');require(isinstance(assets,list),'VERSION_RELEASE_ASSETS_INVALID')
            for asset in assets:
                name=asset.get('name');require(isinstance(name,str),'VERSION_ASSET_NAME_INVALID')
                if not name.lower().endswith('.apk'):continue
                match=APK.fullmatch(name)
                # Unknown APK name cannot establish a safe global floor.
                require(match is not None,'VERSION_UNRECOGNIZED_APK_REVIEW_REQUIRED')
                code=int(match.group(2));require(integer(code,1,MAX_VERSION),'VERSION_RELEASE_CODE_OUT_OF_RANGE');highest=max(highest,code)
        if len(releases)<100:return highest
    require(False,'VERSION_RELEASE_HISTORY_TRUNCATED')


def verify_artifact(client,row: dict,artifact: Path,artifact_id: int)->tuple[dict,bytes|None,str]:
    """Bind a locally retained artifact to authenticated provider metadata.

    The ZIP is downloaded separately by the owner; no credentials or signed
    redirect URLs are copied into the journal. Never extract arbitrary paths.
    """
    import zipfile
    from event_journal import strict_json
    a=row['attempts'][-1];require(a['state']=='qualified','PROMOTION_DIAGNOSTIC_NOT_SUCCESSFUL')
    require(integer(artifact_id,1,2**63-1),'PROMOTION_ARTIFACT_ID_INVALID')
    live=client.request(f"/actions/runs/{a['runId']}")
    from event_journal import title
    require(live.get('id')==a['runId'] and live.get('display_title')==title(row['event'],a) and live.get('status')=='completed' and live.get('conclusion')=='success' and live.get('head_sha')==a['forkSha'] and live.get('head_branch')=='main' and (live.get('head_repository') or {}).get('full_name')==REPO and str(live.get('path','')).split('@',1)[0].removeprefix('/')=='.github/workflows/fork-source-build.yml','PROMOTION_LIVE_RUN_DRIFT')
    meta=client.request(f'/actions/artifacts/{artifact_id}')
    run=meta.get('workflow_run') or {};dg=meta.get('digest','')
    require(meta.get('id')==artifact_id and meta.get('name')==f"f05-promotion-{a['runId']}" and run.get('id')==a['runId'] and run.get('head_sha')==a['forkSha'] and meta.get('expired') is False and isinstance(dg,str) and dg.startswith('sha256:') and HEX256.fullmatch(dg[7:]),'PROMOTION_ARTIFACT_IDENTITY_MISMATCH')
    require(artifact.is_file() and not artifact.is_symlink() and 0<artifact.stat().st_size<=110_000_000,'PROMOTION_ARTIFACT_FILE_INVALID')
    with artifact.open('rb') as f:actual=hashlib.file_digest(f,'sha256').hexdigest()
    require(actual==dg[7:],'PROMOTION_ARTIFACT_DIGEST_MISMATCH')
    with zipfile.ZipFile(artifact) as z:
        names=z.namelist();require(len(names)==len(set(names)) and set(names) in ({'f05-source-provenance.json'},{'f05-source-provenance.json','f05-integration.bundle'}),'PROMOTION_ARTIFACT_MEMBERS_INVALID')
        require(z.getinfo('f05-source-provenance.json').file_size<=1_000_000,'PROMOTION_REPORT_TOO_LARGE')
        report=strict_json(z.read('f05-source-provenance.json'));require(isinstance(report,dict),'PROMOTION_REPORT_INVALID')
        descriptor=report.get('integrationBundle');bundle=None
        if descriptor is not None:
            require(isinstance(descriptor,dict) and set(descriptor)=={'name','sha256','sizeBytes','prerequisite'} and descriptor['name']=='f05-integration.bundle' and descriptor['prerequisite']==a['forkSha'] and 'f05-integration.bundle' in names and integer(descriptor['sizeBytes'],1,100_000_000) and z.getinfo('f05-integration.bundle').file_size==descriptor['sizeBytes'],'PROMOTION_BUNDLE_DESCRIPTOR_INVALID')
            bundle=z.read('f05-integration.bundle');require(hashlib.sha256(bundle).hexdigest()==descriptor['sha256'],'PROMOTION_BUNDLE_DIGEST_MISMATCH')
        else:require(report.get('mergedSha')==a['forkSha'] and len(names)==1,'PROMOTION_BUNDLE_MISSING')
    return report,bundle,actual
