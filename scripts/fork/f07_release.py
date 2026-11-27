#!/usr/bin/env python3
"""F07 guarded promotion of a source-pinned F06 signed manager artifact.

No publication without a reviewed exact run/tag/cert/API entry on fork main,
independent APK re-verification and a committed integrated source ancestor.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
import stat

import release_lineage as lineage
import event_journal as journal
from f06_signing import apk_metadata, fingerprint, sdk_tool, NATIVE_ABIS, Refused as SigningRefused

ROOT = Path(__file__).resolve().parents[2]
REPO = 'Mikeyphw/BakaSU'
RUN_PATH = '.github/workflows/fork-f06-signed-manager.yml'
SHA = re.compile(r'[a-f0-9]{40}\Z')
TAG = re.compile(r'f07-v[0-9][A-Za-z0-9._-]{0,75}\Z')
APK = re.compile(r'BakaSU_([A-Za-z0-9._+-]{1,128})_([1-9][0-9]{0,9})-(arm64-v8a|armeabi-v7a|x86_64|riscv64|universal)-release\.apk\Z')
PACKAGE = 'com.mikeyphw.bakasu'
MAX_RELEASE_PAGES = 20
MAX_APKS = 10
MAX_ARTIFACT_BYTES = 2 * 1024**3
REVIEW_PATH = 'config/fork-release-review.json'


class Refused(RuntimeError):
    pass


def require(condition: object, code: str) -> None:
    if not condition:
        raise Refused(code)


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(args: list[str], *, cwd: Path | None = None, allow_fail: bool = False) -> subprocess.CompletedProcess[str]:
    env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1')
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=240, check=False, env=env)
    if p.returncode and not allow_fail:
        # Never print authorization headers or echo environment secrets.
        raise Refused('COMMAND_FAILED_'+args[0]+'_'+args[1] if len(args)>1 else 'COMMAND_FAILED')
    return p


def git(*args: str) -> str:
    return command(['git','-C',str(ROOT),*args]).stdout.strip()


def api(path: str) -> object:
    require(path.startswith('repos/Mikeyphw/BakaSU/') and '..' not in path and '\\' not in path,
            'F07_API_PATH_REFUSED')
    p = command(['gh','api',path])
    try:
        return journal.strict_json(p.stdout.encode())
    except ValueError:
        raise Refused('F07_API_RESPONSE_INVALID') from None


def context() -> str:
    require(os.getenv('GITHUB_ACTIONS') == 'true' and os.getenv('GITHUB_REPOSITORY') == REPO
            and os.getenv('GITHUB_REF') == 'refs/heads/main', 'F07_FORK_MAIN_ONLY')
    head = git('rev-parse','HEAD')
    require(head == os.getenv('GITHUB_SHA') and SHA.fullmatch(head), 'F07_CHECKOUT_HEAD_DRIFT')
    require(git('status','--porcelain=v1','--untracked-files=all') == '', 'F07_CHECKOUT_DIRTY')
    return head


REVIEW_FIELDS = {'f06RunId','f06RunAttempt','tag','channel','sourceMergedSha','sourceForkSha','sourceTree',
                 'certificateSha256','managerUapi','minimumKernelSuVersion','versionCode','reservationId',
                 'signedProvenanceSha256','evidenceArtifactId','evidenceArtifactSha256','apkArtifactId','apkArtifactSha256'}


def validate_review_entry(e):
    require(isinstance(e,dict) and set(e) == REVIEW_FIELDS, 'F07_REVIEWED_ENTRY_SCHEMA_INVALID')
    require(isinstance(e['tag'],str) and TAG.fullmatch(e['tag']) and e['channel'] in ('beta','stable') and
            (e['channel']=='beta') == ('-beta' in e['tag']), 'F07_TAG_CHANNEL_MISMATCH')
    require(all(isinstance(e[k],str) and SHA.fullmatch(e[k]) for k in ('sourceMergedSha','sourceForkSha','sourceTree')) and
            all(lineage.sha256(e[k]) for k in ('certificateSha256','reservationId','signedProvenanceSha256','evidenceArtifactSha256','apkArtifactSha256')) and
            all(lineage.positive(e[k]) for k in ('f06RunId','f06RunAttempt','evidenceArtifactId','apkArtifactId')) and
            e['evidenceArtifactId'] != e['apkArtifactId'], 'F07_REVIEWED_SOURCE_INVALID')
    require(journal.integer(e['managerUapi'],1,999999) and journal.integer(e['minimumKernelSuVersion'],1,99999999) and
            journal.integer(e['versionCode'],1,journal.MAX_VERSION), 'F07_REVIEWED_COMPATIBILITY_OR_VERSION_INVALID')
    return e


def validated_registry(registry):
    require(isinstance(registry,dict) and registry.get('schemaVersion') == 2 and registry.get('repository') == REPO and
            registry.get('defaultBranch') == 'main' and isinstance(registry.get('approvedCandidates'),list) and
            len(registry['approvedCandidates']) <= journal.MAX_EVENTS, 'F07_REVIEW_REGISTRY_INVALID')
    seen={key:set() for key in ('tag','reservationId','versionCode','f06RunId')}
    for entry in registry['approvedCandidates']:
        validate_review_entry(entry)
        for key,values in seen.items():
            require(entry[key] not in values,'F07_DUPLICATE_REVIEW_'+key)
            values.add(entry[key])
    return registry['approvedCandidates']


def reviewed_entry(registry: dict, run_id: int, tag: str, channel: str) -> dict:
    require(lineage.positive(run_id) and isinstance(tag,str) and TAG.fullmatch(tag) and channel in ('beta','stable'), 'F07_INVALID_DISPATCH_INPUT')
    matches=[x for x in validated_registry(registry) if (x['f06RunId'],x['tag'],x['channel']) == (run_id,tag,channel)]
    require(len(matches)==1,'F07_REVIEWED_CANDIDATE_REQUIRED')
    return matches[0]


def review_continuity(root,head,registry):
    committed=journal.strict_json(lineage.git(root,'show',head+':'+REVIEW_PATH))
    require(committed==registry,'F07_REVIEW_WORKTREE_DRIFT')
    current={x['tag']:x for x in validated_registry(registry)}
    for raw in lineage.history(root,head,REVIEW_PATH):
        if raw['schemaVersion']==1:
            require(raw.get('approvedCandidates')==[],'F07_LEGACY_NONEMPTY_REVIEW_REQUIRES_MIGRATION')
            continue
        require(all(current.get(x['tag'])==x for x in validated_registry(raw)), 'F07_HISTORICAL_REVIEW_REMOVED_OR_CHANGED')


def run_identity(run: dict, entry: dict) -> None:
    try:
        lineage.run_identity(run,entry['f06RunId'],entry['sourceForkSha'],RUN_PATH,entry['f06RunAttempt'])
        require(run.get('display_title') == f"F06/{entry['reservationId']}/{entry['versionCode']}/{entry['sourceForkSha']}",
                'F07_F06_RUN_TITLE_MISMATCH')
    except lineage.Refused as exc:
        raise Refused(str(exc)) from None


def artifact_name(entry, kind):
    require(kind in ('evidence','apk'),'F07_ARTIFACT_KIND_INVALID')
    prefix='f06-source-and-signer-evidence-' if kind=='evidence' else 'f06-signed-manager-diagnostic-'
    return prefix+str(entry['f06RunId'])+'-'+str(entry['f06RunAttempt'])


def verify_f06_artifacts(entry, request=api):
    result={}
    for kind in ('evidence','apk'):
        ident=entry[kind+'ArtifactId']
        try:
            meta=request(f'repos/{REPO}/actions/artifacts/{ident}')
            lineage.artifact_identity(meta,ident,entry[kind+'ArtifactSha256'],entry['f06RunId'],entry['sourceForkSha'],artifact_name(entry,kind))
            require(meta['size_in_bytes']<=MAX_ARTIFACT_BYTES,'F07_PROVIDER_ARTIFACT_TOO_LARGE')
            result[kind]=meta
        except lineage.Refused as exc:
            raise Refused(str(exc)) from None
    return result


def extract_f06_artifact(archive,output,kind,expected_sha):
    require(archive.is_file() and not archive.is_symlink() and 0<archive.stat().st_size<=MAX_ARTIFACT_BYTES and
            digest(archive)==expected_sha,'F07_ARTIFACT_ARCHIVE_DIGEST_MISMATCH')
    require(output.is_dir() and not output.is_symlink() and not any(output.iterdir()),'F07_ARTIFACT_OUTPUT_NOT_EMPTY')
    try:
        with zipfile.ZipFile(archive) as z:
            infos=z.infolist();names=[x.filename for x in infos]
            require(1<=len(names)<=MAX_APKS and len(set(names))==len(names),'F07_ARTIFACT_ZIP_MEMBER_SET_INVALID')
            if kind=='evidence':
                require(set(names)=={'f06-promoted-source.json','f06-signed-provenance.json'},'F07_EVIDENCE_ZIP_MEMBER_SET_INVALID')
            else:
                require(kind=='apk' and all(APK.fullmatch(name) for name in names),'F07_APK_ZIP_MEMBER_SET_INVALID')
            require(sum(x.file_size for x in infos)<=MAX_ARTIFACT_BYTES,'F07_ARTIFACT_ZIP_SIZE_LIMIT')
            for info in infos:
                mode=(info.external_attr>>16)&0xFFFF
                limit=250000 if kind=='evidence' else 1073741824
                require(not info.is_dir() and stat.S_IFMT(mode) in (0,stat.S_IFREG) and not info.flag_bits&1 and
                        0<info.file_size<=limit,'F07_ARTIFACT_ZIP_MEMBER_UNSAFE')
            for info in infos:
                with z.open(info) as src, (output/info.filename).open('xb') as dest:
                    remaining=info.file_size
                    while remaining:
                        chunk=src.read(min(1024*1024,remaining))
                        require(chunk,'F07_ARTIFACT_ZIP_TRUNCATED');dest.write(chunk);remaining-=len(chunk)
                    require(not src.read(1),'F07_ARTIFACT_ZIP_SIZE_DRIFT')
    except (zipfile.BadZipFile,RuntimeError,NotImplementedError) as exc:
        if isinstance(exc,Refused):raise
        raise Refused('F07_ARTIFACT_ZIP_INVALID') from None


def download_f06_artifact(entry,kind,output):
    # Download by reviewed immutable provider ID, not mutable artifact name.
    ident=entry[kind+'ArtifactId'];expected=entry[kind+'ArtifactSha256']
    with tempfile.TemporaryDirectory(prefix='bakasu-f06-archive-') as folder:
        archive=Path(folder)/'artifact.zip'
        with archive.open('xb') as stream:
            p=subprocess.run(['gh','api',f'repos/{REPO}/actions/artifacts/{ident}/zip'],stdout=stream,
                             stderr=subprocess.PIPE,timeout=240,check=False)
        require(p.returncode==0,'F07_ARTIFACT_DOWNLOAD_FAILED')
        extract_f06_artifact(archive,output,kind,expected)


def read_signed_evidence(path,entry):
    require(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=250000,'F07_F06_PROVENANCE_MISSING')
    raw=path.read_bytes()
    require(hashlib.sha256(raw).hexdigest()==entry['signedProvenanceSha256'],'F07_REVIEWED_PROVENANCE_BYTES_DRIFT')
    return journal.strict_json(raw)


def source_identity(source: dict, entry: dict, *, root=ROOT, head=None) -> None:
    require(isinstance(source,dict) and source.get('schemaVersion') == 2 and source.get('status') == 'signed-verified' and
            source.get('mode') == 'F06-signed-artifact-not-a-release' and source.get('repository') == REPO and
            source.get('releaseQualified') is False and source.get('deviceQualified') is False and
            source.get('compatibilityQualified') is False and source.get('reservationId') == entry['reservationId'] and
            source.get('certificateSha256') == entry['certificateSha256'], 'F07_F06_ATTESTATION_INVALID')
    e=source.get('source')
    require(isinstance(e,dict) and set(e)=={'schemaVersion','mode','status','forkSha','reservation','certificateSha256','runId','runAttempt'} and
            e['schemaVersion']==2 and e['mode']=='F06-promoted-reservation' and e['status']=='source-promoted-reviewed' and
            e['forkSha']==entry['sourceForkSha'] and e['runId']==entry['f06RunId'] and e['runAttempt']==entry['f06RunAttempt'] and
            e['certificateSha256']==entry['certificateSha256'], 'F07_F06_SOURCE_PROVENANCE_MISMATCH')
    try:
        row=lineage.validate_reservation(e['reservation'])
        require(all(row[k]==entry[v] for k,v in (('sourceCommit','sourceMergedSha'),('sourceTree','sourceTree'),
                ('reservationId','reservationId'),('versionCode','versionCode'),('channel','channel'))), 'F07_RESERVATION_REVIEW_DRIFT')
        head=head or lineage.git(root,'rev-parse','HEAD').decode().strip()
        require(lineage.ancestor(root,entry['sourceForkSha'],head),'F07_SIGNING_WORKFLOW_NOT_ON_MAIN')
        lineage.committed_source(root,row,entry['sourceForkSha'])
        lineage.committed_source(root,row,head)
        lineage.signer_continuity(root,head,entry['certificateSha256'])
        for commit in (entry['sourceForkSha'],head):
            policy=lineage.policy_at(root,commit)
            require(policy['certificateSha256']==entry['certificateSha256'] and
                    lineage.reviewed_reservation(policy,row['reservationId'],row['versionCode'])==row,'F07_REVIEWED_SIGNER_OR_RESERVATION_DRIFT')
    except lineage.Refused as exc:
        raise Refused(str(exc)) from None


def asset_names(source: dict, entry: dict) -> set[str]:
    cert = entry['certificateSha256']
    rows = source.get('apks')
    require(isinstance(rows,list) and 1 <= len(rows) <= MAX_APKS,
            'F07_F06_APK_INVENTORY_INVALID')
    names=set();codes=set();versions=set();abis=set()
    for row in rows:
        require(isinstance(row,dict) and isinstance(row.get('fileName'),str),
                'F07_F06_APK_ROW_INVALID')
        name=row['fileName'];m=APK.fullmatch(name)
        require(m is not None and name not in names and row.get('packageName')==PACKAGE
                and row.get('signerCertificateSha256') == cert
                and type(row.get('versionCode')) is int and row['versionCode']==entry['versionCode']
                and row.get('versionName')==m.group(1)
                and row.get('nativeAbis')==sorted(NATIVE_ABIS if m.group(3)=='universal' else {m.group(3)})
                and int(m.group(2))==row['versionCode']
                and re.fullmatch('[a-f0-9]{64}',str(row.get('sha256','')))
                and type(row.get('sizeBytes')) is int and 100000 < row['sizeBytes'] <= 1073741824,
                'F07_F06_APK_METADATA_MISMATCH')
        names.add(name);codes.add(row['versionCode']);versions.add(row['versionName']);abis.add(m.group(3))
    require(len(codes)==1 and len(versions)==1 and len(abis)==len(rows),
            'F07_F06_MIXED_VERSION_OR_ABI')
    return names


def prepare_candidate(entry: dict, source: dict, apk_dir: Path, output: Path, sdk_root: Path, signed_path: Path) -> dict:
    require(output.is_dir() and not output.is_symlink() and
            apk_dir.is_dir() and not apk_dir.is_symlink(), 'F07_DIRECTORY_INVALID')
    require(not any(output.iterdir()), 'F07_OUTPUT_MUST_BE_EMPTY')
    names=asset_names(source,entry)
    apks=[x for x in apk_dir.iterdir() if x.is_file() and x.name.endswith('.apk')]
    require({x.name for x in apks}==names and len(apks)==len(names), 'F07_APK_FILES_DIFFER_FROM_ATTESTATION')
    signer=entry['certificateSha256']
    try:
        aapt=str(sdk_tool('aapt',sdk_root))
        apksigner=str(sdk_tool('apksigner',sdk_root))
    except SigningRefused:
        raise Refused('F07_SIGNER_VERIFICATION_TOOL_UNAVAILABLE') from None
    by_name={x['fileName']:x for x in source['apks']};release=[]
    for path in sorted(apks):
        require(not path.is_symlink() and path.stat().st_size==by_name[path.name]['sizeBytes']
                and digest(path)==by_name[path.name]['sha256'], 'F07_APK_HASH_DRIFT')
        try:
            actual=apk_metadata(path,aapt,apksigner,signer,PACKAGE)
        except SigningRefused:
            raise Refused('F07_APK_SIGNATURE_OR_METADATA_REFUSED') from None
        require(all(actual[k]==by_name[path.name][k] for k in
                    ('fileName','sha256','sizeBytes','packageName','versionCode','versionName','nativeAbis','signerCertificateSha256')),
                'F07_APK_REVERIFICATION_MISMATCH')
        abi=APK.fullmatch(path.name).group(3)
        release.append({'fileName':path.name,'versionCode':entry['versionCode'],'abi':abi,
                        'managerUapi':entry['managerUapi'],
                        'minimumKernelSuVersion':entry['minimumKernelSuVersion']})
        shutil.copyfile(path,output/path.name)
    manifest={'schemaVersion':1,'apks':release}
    evidence={'schemaVersion':1,'repository':REPO,'tag':entry['tag'],'channel':entry['channel'],
              'f06RunId':entry['f06RunId'],'sourceMergedSha':entry['sourceMergedSha'],
              'sourceForkSha':entry['sourceForkSha'],'certificateSha256':signer,
              'sourceTree':entry['sourceTree'],'reservationId':entry['reservationId'],
              'f06RunAttempt':entry['f06RunAttempt'],'signedProvenanceSha256':entry['signedProvenanceSha256'],
              'reviewDigest':lineage.digest(entry),
              'status':'release-candidate-reviewed','releasePublished':False,
              'compatibilityEvidence':'reviewed exact-source registry entry',
              'apks':[{'name':p.name,'sha256':digest(p),'sizeBytes':p.stat().st_size} for p in sorted(apks)]}
    require(read_signed_evidence(signed_path,entry)==source,'F07_SIGNED_PROVENANCE_DRIFT')
    shutil.copyfile(signed_path,output/'f06-signed-provenance.json')
    require(digest(output/'f06-signed-provenance.json')==entry['signedProvenanceSha256'],'F07_SIGNED_PROVENANCE_COPY_DRIFT')
    (output/'manager-compatibility.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    (output/'f07-release-provenance.json').write_text(json.dumps(evidence,sort_keys=True,indent=2)+'\n')
    return evidence


def release_inventory():
    observed=[];ids=set();tags=set()
    for page in range(1,MAX_RELEASE_PAGES+1):
        data=api(f'repos/{REPO}/releases?per_page=100&page={page}')
        require(isinstance(data,list) and len(data)<=100,'F07_RELEASES_PAGE_INVALID')
        for rel in data:
            require(isinstance(rel,dict) and lineage.positive(rel.get('id')) and rel['id'] not in ids and
                    isinstance(rel.get('tag_name'),str) and rel['tag_name'] not in tags and
                    type(rel.get('draft')) is bool and isinstance(rel.get('assets'),list),'F07_RELEASE_HISTORY_AMBIGUOUS')
            ids.add(rel['id']);tags.add(rel['tag_name']);observed.append(rel)
        if len(data)<100:return observed
    raise Refused('F07_RELEASE_HISTORY_TOO_LARGE')


def check_previous_versions(version: int, *, excluding_tag='', releases=None) -> None:
    highest=0
    for rel in release_inventory() if releases is None else releases:
        if rel['draft'] or rel['tag_name']==excluding_tag:continue
        for asset in rel['assets']:
            name=asset.get('name')
            require(isinstance(name,str),'F07_RELEASE_ASSET_NAME_INVALID')
            if not name.lower().endswith('.apk'):continue
            match=APK.fullmatch(name)
            require(match is not None and journal.integer(int(match.group(2)),1,journal.MAX_VERSION),'F07_UNKNOWN_RELEASE_APK_REVIEW_REQUIRED')
            highest=max(highest,int(match.group(2)))
    require(version>highest,'F07_VERSION_CODE_NOT_MONOTONIC')


def read_tag(tag: str):
    p=command(['gh','api',f'repos/{REPO}/git/ref/tags/{tag}'],allow_fail=True)
    if p.returncode==0:
        data=journal.strict_json(p.stdout.encode())
        require(isinstance(data,dict) and data.get('ref')=='refs/tags/'+tag and isinstance(data.get('object'),dict),'F07_TAG_PROBE_INVALID')
        return data['object']
    require('HTTP 404' in p.stderr,'F07_TAG_PROBE_FAILED')
    return None


def preflight_release_tag(tag: str) -> None:
    require(read_tag(tag) is None,'F07_RELEASE_TAG_ALREADY_EXISTS')


def exact_remote_head(head):
    require(head==git('rev-parse','HEAD'),'F07_MAIN_CHANGED_BEFORE_RELEASE')
    ref=api(f'repos/{REPO}/git/ref/heads/main')
    require(ref.get('ref')=='refs/heads/main' and (ref.get('object') or {}).get('sha')==head,'F07_REMOTE_MAIN_HEAD_DRIFT')


def release_notes(entry):
    return f'Source-bound BakaSU {entry["channel"]} signed manager. Review SHA-256: {lineage.digest(entry)}'


def draft_identity(release,entry):
    require(isinstance(release,dict) and lineage.positive(release.get('id')) and release.get('tag_name')==entry['tag'] and
            release.get('target_commitish')==entry['sourceMergedSha'] and release.get('prerelease') is (entry['channel']=='beta') and
            type(release.get('draft')) is bool and release.get('body')==release_notes(entry) and isinstance(release.get('assets'),list),
            'F07_RELEASE_TRANSACTION_IDENTITY_MISMATCH')


def asset_readback(release,output, *, complete):
    names={x.name for x in output.iterdir()}
    rows=release['assets'];by_name={}
    for asset in rows:
        require(isinstance(asset,dict) and isinstance(asset.get('name'),str) and asset['name'] in names and asset['name'] not in by_name and
                lineage.positive(asset.get('id')) and type(asset.get('size')) is int and asset['size']==(output/asset['name']).stat().st_size and
                asset.get('digest')=='sha256:'+digest(output/asset['name']) and asset.get('state')=='uploaded','F07_RELEASE_ASSET_IDENTITY_MISMATCH')
        by_name[asset['name']]=asset
    require(not complete or set(by_name)==names,'F07_RELEASE_ASSET_SET_MISMATCH')
    # Download independently by immutable asset ID, including private draft assets.
    with tempfile.TemporaryDirectory(prefix='bakasu-f07-readback-') as folder:
        for name,asset in sorted(by_name.items()):
            p=Path(folder)/name
            # Stream to a private file instead of retaining APK bytes in memory.
            with p.open('xb') as stream:
                proc=subprocess.run(['gh','api',f'repos/{REPO}/releases/assets/{asset["id"]}','-H','Accept: application/octet-stream'],
                                    stdout=stream,stderr=subprocess.PIPE,timeout=240,check=False)
            require(proc.returncode==0 and p.stat().st_size==(output/name).stat().st_size and digest(p)==digest(output/name),
                    'F07_RELEASE_DOWNLOAD_SHA256_MISMATCH')
    return names-set(by_name)


def fresh_run_guard(entry):
    run_id=int(os.environ.get('GITHUB_RUN_ID','0'));attempt=int(os.environ.get('GITHUB_RUN_ATTEMPT','0'))
    require(lineage.positive(run_id) and attempt==1,'F07_FRESH_REQUIRES_FIRST_ATTEMPT')
    seen=set();total=None;found=False
    title=f'F07/{entry["tag"]}/'
    for page in range(1,MAX_RELEASE_PAGES+1):
        data=api(f'repos/{REPO}/actions/workflows/fork-f07-release.yml/runs?event=workflow_dispatch&per_page=100&page={page}')
        require(isinstance(data,dict) and type(data.get('total_count')) is int and data['total_count']>=0 and isinstance(data.get('workflow_runs'),list) and len(data['workflow_runs'])<=100,'F07_RUN_HISTORY_INVALID')
        if total is None:total=data['total_count']
        require(total==data['total_count'],'F07_RUN_HISTORY_CHANGED')
        for run in data['workflow_runs']:
            require(isinstance(run,dict) and lineage.positive(run.get('id')) and run['id'] not in seen,'F07_RUN_HISTORY_AMBIGUOUS')
            seen.add(run['id']);name=run.get('display_title','')
            require(isinstance(name,str),'F07_RUN_TITLE_INVALID')
            if run['id']==run_id:
                require(name==title+str(entry['f06RunId']),'F07_CURRENT_RUN_TITLE_INVALID');found=True
            else:
                require(not name.startswith(title),'F07_PRIOR_PUBLICATION_INTENT_REVIEW_REQUIRED')
        require(len(seen)<=total,'F07_RUN_HISTORY_CHANGED')
        if len(seen)==total:
            require(found,'F07_CURRENT_RUN_NOT_OBSERVED');return
        require(data['workflow_runs'],'F07_RUN_HISTORY_TRUNCATED')
    raise Refused('F07_RUN_HISTORY_TRUNCATED')


def publish(entry: dict, output: Path, *, head: str, resume=False) -> None:
    tag=entry['tag'];assets=sorted(str(x) for x in output.iterdir())
    require(4<=len(assets)<=MAX_APKS+3 and all(x.is_file() and not x.is_symlink() for x in output.iterdir()),'F07_PUBLISH_ASSET_COUNT_INVALID')
    exact_remote_head(head)
    releases=release_inventory();matches=[x for x in releases if x['tag_name']==tag]
    require(len(matches)<=1,'F07_RELEASE_TRANSACTION_AMBIGUOUS')
    check_previous_versions(entry['versionCode'],excluding_tag=tag if resume else '',releases=releases)
    if not resume:
        require(not matches,'F07_EXISTING_TRANSACTION_REQUIRES_RESUME')
        fresh_run_guard(entry)
        preflight_release_tag(tag)
        exact_remote_head(head)
        # Deliberate single mutation. An uncertain exit is not retried. A
        # later explicit resume can only adopt an observed matching release.
        cmd=['gh','release','create',tag,*assets,'-R',REPO,'--target',entry['sourceMergedSha'],
             '--title',tag,'--notes',release_notes(entry),'--draft']
        if entry['channel']=='beta':cmd.append('--prerelease')
        command(cmd)
        releases=release_inventory();matches=[x for x in releases if x['tag_name']==tag]
    require(len(matches)==1,'F07_NO_OBSERVED_TRANSACTION_NEVER_RECREATE')
    observed=matches[0];draft_identity(observed,entry);rid=observed['id']
    tag_object=read_tag(tag)
    require(tag_object is None and observed['draft'] or tag_object=={'type':'commit','sha':entry['sourceMergedSha']} or
            isinstance(tag_object,dict) and tag_object.get('type')=='commit' and tag_object.get('sha')==entry['sourceMergedSha'],'F07_TRANSACTION_TAG_DRIFT')
    if not observed['draft']:
        require(resume and observed.get('published_at'),'F07_PUBLISHED_TRANSACTION_REQUIRES_RESUME')
        asset_readback(observed,output,complete=True)
        print('F07_ALREADY_PUBLISHED_VERIFIED tag='+tag,flush=True);return
    missing=asset_readback(observed,output,complete=False)
    if missing:
        require(resume,'F07_DRAFT_PARTIAL_REQUIRES_EXPLICIT_RESUME')
        exact_remote_head(head)
        command(['gh','release','upload',tag,*[str(output/name) for name in sorted(missing)],'-R',REPO])
    # Re-read and prove exact draft identity and every byte before publishing.
    observed=api(f'repos/{REPO}/releases/{rid}');draft_identity(observed,entry)
    require(observed['id']==rid and observed['draft'],'F07_DRAFT_STATE_DRIFT')
    asset_readback(observed,output,complete=True)
    check_previous_versions(entry['versionCode'])
    exact_remote_head(head)
    tag_object=read_tag(tag)
    require(tag_object is None or tag_object.get('type')=='commit' and tag_object.get('sha')==entry['sourceMergedSha'],'F07_TRANSACTION_TAG_DRIFT')
    command(['gh','release','edit',tag,'-R',REPO,'--draft=false'])
    final=api(f'repos/{REPO}/releases/{rid}');draft_identity(final,entry)
    require(final['id']==rid and final['draft'] is False and final.get('published_at'),'F07_PUBLISH_POSTCHECK_FAILED')
    tag_object=read_tag(tag)
    require(isinstance(tag_object,dict) and tag_object.get('type')=='commit' and tag_object.get('sha')==entry['sourceMergedSha'],'F07_PUBLISHED_TAG_DRIFT')
    asset_readback(final,output,complete=True)
    print('F07_PUBLISHED_VERIFIED tag='+tag+' source='+entry['sourceMergedSha'],flush=True)


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--f06-run-id',required=True,type=int)
    p.add_argument('--tag',required=True)
    p.add_argument('--channel',required=True,choices=['beta','stable'])
    p.add_argument('--publish',action='store_true')
    p.add_argument('--resume',action='store_true')
    args=p.parse_args(argv)
    try:
        head=context()
        require(not args.resume or args.publish,'F07_RESUME_REQUIRES_PUBLICATION_APPROVAL')
        registry=lineage.read_json(ROOT/'config/fork-release-review.json')
        entry=reviewed_entry(registry,args.f06_run_id,args.tag,args.channel)
        review_continuity(ROOT,head,registry)
        run=api(f'repos/{REPO}/actions/runs/{args.f06_run_id}')
        run_identity(run,entry)
        verify_f06_artifacts(entry)
        # Never download another repo's assets or publish an unverified artifact.
        with tempfile.TemporaryDirectory(prefix='bakasu-f07-') as td:
            base=Path(td);evidence=base/'evidence';evidence.mkdir();apks=base/'apks';apks.mkdir()
            download_f06_artifact(entry,'evidence',evidence)
            download_f06_artifact(entry,'apk',apks)
            report=evidence/'f06-signed-provenance.json'
            signed=read_signed_evidence(report,entry)
            source_identity(signed,entry,head=head)
            require(lineage.read_json(evidence/'f06-promoted-source.json')==signed['source'],'F07_SOURCE_REPORT_DRIFT')
            dest=base/'release';dest.mkdir()
            sdk=Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '/nonexistent-sdk')
            prepare_candidate(entry,signed,apks,dest,sdk,report)
            if not args.resume:check_previous_versions(entry['versionCode'])
            print('F07_CANDIDATE_VERIFIED tag='+entry['tag']+' f06_run='+str(args.f06_run_id)+
                  ' publisher='+str(args.publish).lower(),flush=True)
            if args.publish:publish(entry,dest,head=head,resume=args.resume)
            else:print('F07_QUALIFIED_ONLY_NO_RELEASE_PUBLISHED',flush=True)
        return 0
    except (Refused,ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print('F07_REFUSED '+str(exc),file=sys.stderr,flush=True)
        return 2


if __name__=='__main__':raise SystemExit(main())
