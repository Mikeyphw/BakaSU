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

from f06_signing import apk_metadata, fingerprint, sdk_tool, Refused as SigningRefused

ROOT = Path(__file__).resolve().parents[2]
REPO = 'Mikeyphw/BakaSU'
RUN_PATH = '.github/workflows/fork-f06-signed-manager.yml'
SHA = re.compile(r'[a-f0-9]{40}\Z')
TAG = re.compile(r'f07-v[0-9][A-Za-z0-9._-]{0,75}\Z')
APK = re.compile(r'BakaSU_(.+)_([0-9]+)-(arm64-v8a|armeabi-v7a|x86_64|universal)-release\.apk\Z')
PACKAGE = 'com.mikeyphw.bakasu'
MAX_RELEASE_PAGES = 20
MAX_APKS = 10


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
        return json.loads(p.stdout)
    except ValueError:
        raise Refused('F07_API_RESPONSE_INVALID') from None


def context() -> str:
    require(os.getenv('GITHUB_ACTIONS') == 'true' and os.getenv('GITHUB_REPOSITORY') == REPO
            and os.getenv('GITHUB_REF') == 'refs/heads/main', 'F07_FORK_MAIN_ONLY')
    head = git('rev-parse','HEAD')
    require(head == os.getenv('GITHUB_SHA') and SHA.fullmatch(head), 'F07_CHECKOUT_HEAD_DRIFT')
    require(git('status','--porcelain=v1','--untracked-files=all') == '', 'F07_CHECKOUT_DIRTY')
    return head


def reviewed_entry(registry: dict, run_id: int, tag: str, channel: str) -> dict:
    require(type(run_id) is int and run_id > 0 and TAG.fullmatch(tag) and channel in ('beta','stable'),
            'F07_INVALID_DISPATCH_INPUT')
    require(isinstance(registry,dict) and registry.get('schemaVersion') == 1
            and registry.get('repository') == REPO and registry.get('defaultBranch') == 'main'
            and isinstance(registry.get('approvedCandidates'),list), 'F07_REVIEW_REGISTRY_INVALID')
    matches = [x for x in registry['approvedCandidates'] if isinstance(x,dict)
               and x.get('f06RunId') == run_id and x.get('tag') == tag and x.get('channel') == channel]
    require(len(matches) == 1, 'F07_REVIEWED_CANDIDATE_REQUIRED')
    e = matches[0]
    require(set(e)=={'f06RunId','tag','channel','sourceMergedSha','sourceForkSha',
                     'certificateSha256','managerUapi','minimumKernelSuVersion','versionCode'},
            'F07_REVIEWED_ENTRY_SCHEMA_INVALID')
    require(all(isinstance(e[k],str) and SHA.fullmatch(e[k]) for k in ('sourceMergedSha','sourceForkSha')),
            'F07_REVIEWED_SOURCE_INVALID')
    require(type(e['managerUapi']) is int and 0 < e['managerUapi'] < 1000000 and
            type(e['minimumKernelSuVersion']) is int and 0 < e['minimumKernelSuVersion'] < 100000000 and
            type(e['versionCode']) is int and 0 < e['versionCode'] < 2100000000,
            'F07_REVIEWED_COMPATIBILITY_OR_VERSION_INVALID')
    try:
        fingerprint(e['certificateSha256'])
    except SigningRefused:
        raise Refused('F07_CERT_SHA256_INVALID') from None
    require(e['certificateSha256'] == e['certificateSha256'].lower(), 'F07_CERT_NOT_CANONICAL')
    require((channel == 'beta') == ('-beta' in tag), 'F07_TAG_CHANNEL_MISMATCH')
    return e


def run_identity(run: dict, entry: dict) -> None:
    require(isinstance(run,dict) and run.get('id') == entry['f06RunId']
            and run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and run.get('event') == 'workflow_dispatch' and run.get('head_branch') == 'main'
            and run.get('head_sha') == entry['sourceForkSha'], 'F07_F06_RUN_IDENTITY_MISMATCH')
    require((run.get('head_repository') or {}).get('full_name') == REPO
            and str(run.get('path','')).split('@',1)[0].removeprefix('/') in (RUN_PATH, REPO+'/'+RUN_PATH), 'F07_F06_WORKFLOW_ORIGIN_REFUSED')
    require(type(run.get('run_attempt')) is int and run['run_attempt'] >= 1,
            'F07_F06_ATTEMPT_INVALID')


def source_identity(source: dict, entry: dict, git_checker=git) -> None:
    require(isinstance(source,dict) and source.get('status') == 'signed-verified'
            and source.get('mode') == 'F06-signed-artifact-not-a-release'
            and source.get('repository') == REPO
            and source.get('releaseQualified') is False and source.get('deviceQualified') is False
            and source.get('compatibilityQualified') is False, 'F07_F06_ATTESTATION_INVALID')
    evidence = source.get('source') or {}
    require(evidence.get('forkSha') == entry['sourceForkSha']
            and evidence.get('mergedSha') == entry['sourceMergedSha']
            and SHA.fullmatch(str(evidence.get('mergedTreeSha', '')))
            and SHA.fullmatch(str(evidence.get('upstreamSha', '')))
            and evidence.get('channel') == entry['channel']
            and type(evidence.get('upstreamEventId')) is int and evidence['upstreamEventId'] > 0,
            'F07_F06_SOURCE_PROVENANCE_MISMATCH')
    try:
        actual_cert=fingerprint(source.get('certificateSha256',''))
    except SigningRefused:
        raise Refused('F07_F06_SIGNER_MALFORMED') from None
    require(actual_cert == entry['certificateSha256'], 'F07_F06_SIGNER_MISMATCH')
    # The exact integrated source must actually exist in committed fork main history.
    require(git_checker('rev-parse',entry['sourceMergedSha']+'^{commit}') == entry['sourceMergedSha']
            and git_checker('rev-parse',entry['sourceMergedSha']+'^{tree}') == evidence['mergedTreeSha'],
            'F07_INTEGRATED_SOURCE_UNCOMMITTED')
    ancestor = subprocess.run(['git','-C',str(ROOT),'merge-base','--is-ancestor',entry['sourceMergedSha'],
                               'HEAD'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,
                               env=dict(os.environ,GIT_NO_REPLACE_OBJECTS='1'))
    require(ancestor.returncode == 0, 'F07_INTEGRATED_SOURCE_NOT_ON_MAIN')


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
                and int(m.group(2))==row['versionCode']
                and re.fullmatch('[a-f0-9]{64}',str(row.get('sha256','')))
                and type(row.get('sizeBytes')) is int and row['sizeBytes']>100000,
                'F07_F06_APK_METADATA_MISMATCH')
        names.add(name);codes.add(row['versionCode']);versions.add(row['versionName']);abis.add(m.group(3))
    require(len(codes)==1 and len(versions)==1 and len(abis)==len(rows),
            'F07_F06_MIXED_VERSION_OR_ABI')
    return names


def prepare_candidate(entry: dict, source: dict, apk_dir: Path, output: Path, sdk_root: Path) -> dict:
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
                    ('fileName','sha256','sizeBytes','packageName','versionCode','versionName','signerCertificateSha256')),
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
              'status':'release-candidate-reviewed','releasePublished':False,
              'compatibilityEvidence':'reviewed exact-source registry entry',
              'apks':[{'name':p.name,'sha256':digest(p),'sizeBytes':p.stat().st_size} for p in sorted(apks)]}
    (output/'manager-compatibility.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    (output/'f07-release-provenance.json').write_text(json.dumps(evidence,sort_keys=True,indent=2)+'\n')
    return evidence


def check_previous_versions(version: int) -> None:
    highest=0
    for page in range(1,MAX_RELEASE_PAGES+1):
        data=api(f'repos/{REPO}/releases?per_page=100&page={page}')
        require(isinstance(data,list), 'F07_RELEASES_PAGE_INVALID')
        for rel in data:
            if rel.get('draft'):continue
            for asset in rel.get('assets',[]):
                name=asset.get('name','')
                m=APK.fullmatch(name)
                if m:
                    highest=max(highest,int(m.group(2)))
        if len(data)<100:break
    else:raise Refused('F07_RELEASE_HISTORY_TOO_LARGE')
    require(version>highest,'F07_VERSION_CODE_NOT_MONOTONIC')


def preflight_release_tag(tag: str) -> None:
    # A tag must not exist before the draft is created, including tags without releases.
    p=command(['gh','api',f'repos/{REPO}/git/ref/tags/{tag}'],allow_fail=True)
    if p.returncode==0:raise Refused('F07_RELEASE_TAG_ALREADY_EXISTS')
    require('HTTP 404' in p.stderr or 'Not Found' in p.stderr, 'F07_TAG_PROBE_FAILED')


def publish(entry: dict, output: Path, *, head: str) -> None:
    tag=entry['tag'];release_assets=sorted(str(x) for x in output.iterdir())
    require(len(release_assets)>=3 and len(release_assets)<=MAX_APKS+2, 'F07_PUBLISH_ASSET_COUNT_INVALID')
    require(head==git('rev-parse','HEAD'), 'F07_MAIN_CHANGED_BEFORE_RELEASE')
    ref=api(f'repos/{REPO}/git/ref/heads/main')
    require((ref.get('object') or {}).get('sha')==head, 'F07_REMOTE_MAIN_HEAD_DRIFT')
    check_previous_versions(entry['versionCode'])
    preflight_release_tag(tag)
    # Prefix f07-v deliberately avoids legacy release.yml `v*` tag triggers.
    require(tag.startswith('f07-v'), 'F07_LEGACY_RELEASE_TRIGGER_BLOCK')
    cmd=['gh','release','create',tag,*release_assets,'-R',REPO,'--target',entry['sourceMergedSha'],
         '--title',tag,'--notes',f'Source-bound BakaSU {entry["channel"]} signed manager. See release provenance.',
         '--draft']
    if entry['channel']=='beta':cmd.append('--prerelease')
    command(cmd)
    observed=api(f'repos/{REPO}/releases/tags/{tag}')
    require(observed.get('draft') is True and observed.get('tag_name') == tag
            and observed.get('target_commitish') == entry['sourceMergedSha']
            and bool(observed.get('prerelease')) == (entry['channel']=='beta'),
            'F07_DRAFT_RELEASE_IDENTITY_MISMATCH')
    names={x.name for x in output.iterdir()}
    actual={x.get('name') for x in observed.get('assets',[])}
    require(actual==names, 'F07_DRAFT_ASSET_SET_MISMATCH')
    with tempfile.TemporaryDirectory(prefix='bakasu-f07-download-') as tmp:
        command(['gh','release','download',tag,'-R',REPO,'-D',tmp])
        downloaded={x.name for x in Path(tmp).iterdir()}
        require(downloaded==names, 'F07_DRAFT_DOWNLOAD_INVENTORY_MISMATCH')
        for name in names:
            require(digest(Path(tmp)/name)==digest(output/name),'F07_DRAFT_DOWNLOAD_SHA256_MISMATCH')
    # Only after full readback does the draft become publicly visible.
    command(['gh','release','edit',tag,'-R',REPO,'--draft=false'])
    final=api(f'repos/{REPO}/releases/tags/{tag}')
    require(final.get('draft') is False and final.get('tag_name')==tag,
            'F07_PUBLISH_POSTCHECK_FAILED')
    print('F07_PUBLISHED_VERIFIED tag='+tag+' source='+entry['sourceMergedSha'],flush=True)


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--f06-run-id',required=True,type=int)
    p.add_argument('--tag',required=True)
    p.add_argument('--channel',required=True,choices=['beta','stable'])
    p.add_argument('--publish',action='store_true')
    args=p.parse_args(argv)
    try:
        head=context()
        registry=json.loads((ROOT/'config/fork-release-review.json').read_text())
        entry=reviewed_entry(registry,args.f06_run_id,args.tag,args.channel)
        run=api(f'repos/{REPO}/actions/runs/{args.f06_run_id}')
        run_identity(run,entry)
        # Never download another repo's assets or publish an unverified artifact.
        with tempfile.TemporaryDirectory(prefix='bakasu-f07-') as td:
            base=Path(td);evidence=base/'evidence';evidence.mkdir();apks=base/'apks';apks.mkdir()
            command(['gh','run','download',str(args.f06_run_id),'-R',REPO,
                     '-n',f'f06-source-and-signer-evidence-{args.f06_run_id}','-D',str(evidence)])
            command(['gh','run','download',str(args.f06_run_id),'-R',REPO,
                     '-n',f'f06-signed-manager-diagnostic-{args.f06_run_id}','-D',str(apks)])
            report=evidence/'f06-signed-provenance.json'
            require(report.is_file() and not report.is_symlink() and report.stat().st_size<250000,
                    'F07_F06_PROVENANCE_MISSING')
            signed=json.loads(report.read_text())
            source_identity(signed,entry)
            dest=base/'release';dest.mkdir()
            sdk=Path(os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT') or '/nonexistent-sdk')
            prepare_candidate(entry,signed,apks,dest,sdk)
            check_previous_versions(entry['versionCode'])
            print('F07_CANDIDATE_VERIFIED tag='+entry['tag']+' f06_run='+str(args.f06_run_id)+
                  ' publisher='+str(args.publish).lower(),flush=True)
            if args.publish:publish(entry,dest,head=head)
            else:print('F07_QUALIFIED_ONLY_NO_RELEASE_PUBLISHED',flush=True)
        return 0
    except (Refused,ValueError,OSError,KeyError,subprocess.TimeoutExpired) as exc:
        print('F07_REFUSED '+str(exc),file=sys.stderr,flush=True)
        return 2


if __name__=='__main__':raise SystemExit(main())
