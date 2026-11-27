#!/usr/bin/env python3
"""F05 source-pinned, conflict-refusing, unsigned diagnostic manager builds.

This does not sign or publish releases. It integrates a validated upstream
commit into a disposable GitHub-hosted checkout of the exact fork SHA.
Never operates on a device and never pushes source changes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

UPSTREAM = 'Baka-SU/BakaSU'
FORK = 'Mikeyphw/BakaSU'
SHA = re.compile(r'^[a-f0-9]{40}$')
TAG = re.compile(r'^v[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')


class StageError(RuntimeError):
    pass


class UpstreamClient:
    def __init__(self, token: str = ''):
        self.token = token

    def get(self, path: str):
        if not path.startswith('/') or path.startswith('//') or '\\' in path:
            raise StageError('INVALID_UPSTREAM_API_PATH')
        req = Request(
            'https://api.github.com/repos/' + UPSTREAM + path,
            headers={
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'BakaSU-fork-f05-source-pin',
                **({'Authorization': 'Bearer ' + self.token} if self.token else {}),
            },
        )
        try:
            with urlopen(req, timeout=25) as response:
                raw = response.read(4_000_001)
                if len(raw) > 4_000_000:
                    raise StageError('UPSTREAM_RESPONSE_TOO_LARGE')
                return json.loads(raw)
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            raise StageError(f'UPSTREAM_API_REFUSED status={getattr(exc, "code", "network")}') from None


def resolve_tag(client: UpstreamClient, tag: str) -> str:
    if TAG.fullmatch(tag) is None:
        raise StageError('STABLE_TAG_INVALID')
    ref = client.get('/git/ref/tags/' + quote(tag, safe=''))
    obj = ref.get('object') if isinstance(ref, dict) else None
    for _ in range(5):
        if not isinstance(obj, dict) or not isinstance(obj.get('sha'), str) or SHA.fullmatch(obj['sha']) is None:
            raise StageError('INVALID_STABLE_TAG_OBJECT')
        if obj.get('type') == 'commit':
            return obj['sha']
        if obj.get('type') != 'tag':
            raise StageError('STABLE_TAG_NOT_A_COMMIT')
        target = client.get('/git/tags/' + obj['sha'])
        obj = target.get('object') if isinstance(target, dict) else None
    raise StageError('TAG_REFERENCE_TOO_DEEP')


def verify_event(client: UpstreamClient, channel: str, sha: str, event_id: int) -> dict:
    if channel not in ('beta', 'stable') or SHA.fullmatch(sha) is None or event_id <= 0:
        raise StageError('UNTRUSTED_F05_INPUT')
    if channel == 'beta':
        event = client.get(f'/actions/runs/{event_id}')
        if not isinstance(event, dict):
            raise StageError('BETA_EVENT_SCHEMA_INVALID')
        source = event.get('head_repository')
        if (event.get('head_sha') != sha or event.get('head_branch') != 'main'
                or event.get('event') != 'push' or event.get('status') != 'completed'
                or event.get('conclusion') != 'success'
                or not isinstance(source, dict) or source.get('full_name') != UPSTREAM
                or not str(event.get('path', '')).endswith('/build-manager.yml')):
            raise StageError('UPSTREAM_BETA_EVENT_NOT_QUALIFIED')
        return {'channel': channel, 'upstreamSha': sha, 'upstreamRunId': event_id,
                'sourceUrl': f'https://github.com/{UPSTREAM}/actions/runs/{event_id}'}
    event = client.get(f'/releases/{event_id}')
    if not isinstance(event, dict) or event.get('draft') is not False or event.get('prerelease') is not False:
        raise StageError('UPSTREAM_STABLE_RELEASE_NOT_QUALIFIED')
    tag = event.get('tag_name')
    if not isinstance(tag, str) or resolve_tag(client, tag) != sha:
        raise StageError('STABLE_TAG_SOURCE_MISMATCH')
    if not isinstance(event.get('published_at'), str) or not event['published_at']:
        raise StageError('STABLE_NOT_PUBLISHED')
    return {'channel': channel, 'upstreamSha': sha, 'upstreamReleaseId': event_id,
            'upstreamTag': tag, 'sourceUrl': f'https://github.com/{UPSTREAM}/releases/tag/{quote(tag, safe="")}' }


def git(root: Path, *args: str, check: bool = True) -> str:
    p = subprocess.run(['git', *args], cwd=root, text=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=False)
    if check and p.returncode:
        # Git stderr may include remote content; do not print environment or tokens.
        raise StageError(f'GIT_FAILED command={args[0]} rc={p.returncode} stderr={p.stderr[-1200:].strip()}')
    return p.stdout.strip()


def integration(root: Path, fork_sha: str, upstream_sha: str, *,
                fetch_url: str = 'https://github.com/Baka-SU/BakaSU.git') -> dict:
    if SHA.fullmatch(fork_sha) is None or SHA.fullmatch(upstream_sha) is None:
        raise StageError('INVALID_INTEGRATION_SHA')
    if git(root, 'rev-parse', 'HEAD') != fork_sha:
        raise StageError('FORK_CHECKOUT_SHA_MISMATCH')
    if git(root, 'status', '--porcelain=v1', '--untracked-files=all'):
        raise StageError('CHECKOUT_DIRTY_BEFORE_INTEGRATION')
    # Only read from the upstream public repo; never push or force update refs.
    git(root, 'fetch', '--no-tags', fetch_url, upstream_sha)
    if git(root, 'rev-parse', 'FETCH_HEAD^{commit}') != upstream_sha:
        raise StageError('FETCHED_UPSTREAM_SHA_MISMATCH')
    if git(root, 'merge-base', fork_sha, upstream_sha) == '':
        raise StageError('UPSTREAM_NO_COMMON_ANCESTOR')
    is_ancestor = subprocess.run(['git', 'merge-base', '--is-ancestor', upstream_sha, fork_sha],
                                 cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if is_ancestor:
        return {'forkSha': fork_sha, 'upstreamSha': upstream_sha,
                'mergedSha': fork_sha, 'mergedTreeSha': git(root, 'rev-parse', 'HEAD^{tree}'),
                'changedPaths': [], 'integrationMode': 'already-ancestor'}
    proc = subprocess.run(
        ['git', '-c', 'user.name=BakaSU Fork CI', '-c', 'user.email=ci@users.noreply.github.com',
         'merge', '--no-edit', '--no-ff', '--no-gpg-sign', upstream_sha],
        cwd=root, text=True, capture_output=True,
    )
    if proc.returncode:
        conflicts = git(root, 'diff', '--name-only', '--diff-filter=U', check=False).splitlines()
        git(root, 'merge', '--abort', check=False)
        raise StageError('UPSTREAM_MERGE_CONFLICT ' + ','.join(conflicts[:40]))
    merged_sha = git(root, 'rev-parse', 'HEAD')
    tree = git(root, 'rev-parse', 'HEAD^{tree}')
    parents = git(root, 'rev-list', '--parents', '-n', '1', 'HEAD').split()
    if len(parents) != 3 or parents[1:] != [fork_sha, upstream_sha]:
        raise StageError('MERGE_PARENT_PROVENANCE_MISMATCH')
    if git(root, 'status', '--porcelain=v1', '--untracked-files=all'):
        raise StageError('MERGED_CHECKOUT_DIRTY')
    changed = git(root, 'diff', '--name-only', fork_sha, merged_sha).splitlines()
    return {'forkSha': fork_sha, 'upstreamSha': upstream_sha, 'mergedSha': merged_sha,
            'mergedTreeSha': tree, 'changedPaths': changed, 'integrationMode': 'merge-commit'}


def stage(root: Path, channel: str, upstream_sha: str, event_id: int,
          fork_sha: str, report_path: Path, client: UpstreamClient) -> int:
    record = {'schemaVersion': 1, 'mode': 'F05-unsigned-diagnostic-only',
              'channel': channel, 'forkSha': fork_sha, 'upstreamSha': upstream_sha,
              'upstreamEventId': event_id, 'status': 'failed'}
    try:
        if os.environ.get('GITHUB_REPOSITORY') != FORK or os.environ.get('GITHUB_REF') != 'refs/heads/main':
            raise StageError('F05_NOT_RUNNING_ON_FORK_MAIN')
        verified = verify_event(client, channel, upstream_sha, event_id)
        merged = integration(root, fork_sha, upstream_sha)
        record.update(verified)
        record.update(merged)
        record['status'] = 'source-integrated'
        print('BK_F05_SOURCE_INTEGRATION_PASS fork=' + fork_sha + ' upstream=' + upstream_sha
              + ' merged=' + merged['mergedSha'])
        return 0
    except (StageError, ValueError, OSError) as exc:
        record['failure'] = str(exc)
        print('BK_F05_SOURCE_INTEGRATION_REFUSED ' + str(exc), file=sys.stderr)
        return 2
    finally:
        report_path.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def finalize(report_path: Path, apk_dir: Path) -> int:
    record = json.loads(report_path.read_text(encoding='utf-8'))
    if record.get('status') != 'source-integrated':
        raise StageError('F05_BUILD_SOURCE_NOT_QUALIFIED')
    if not apk_dir.is_dir():
        raise StageError('NO_DEBUG_APK_DIRECTORY')
    apks = sorted(apk_dir.glob('*.apk'))
    if not apks or len(apks) > 12:
        raise StageError('NO_OR_TOO_MANY_APKS')
    record['apkChecksums'] = {}
    for apk in apks:
        if apk.is_symlink() or not apk.is_file() or apk.stat().st_size < 100_000:
            raise StageError('INVALID_DEBUG_APK_ARTIFACT')
        with apk.open('rb') as handle:
            record['apkChecksums'][apk.name] = hashlib.file_digest(handle, 'sha256').hexdigest()
    record['status'] = 'debug-build-validated'
    report_path.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print('BK_F05_UNSIGNED_DEBUG_APK_PASS count=' + str(len(apks)))
    print('BK_F05_NOT_A_RELEASE_NOT_SIGNED_WITH_PERSISTENT_KEY')
    return 0


def export_bundle(report_path: Path, output: Path, root: Path) -> int:
    record=json.loads(report_path.read_text(encoding='utf-8'))
    if record.get('status')!='debug-build-validated' or not all(SHA.fullmatch(str(record.get(k,''))) for k in ('forkSha','mergedSha','mergedTreeSha')):
        raise StageError('F05_BUNDLE_SOURCE_NOT_QUALIFIED')
    if git(root,'rev-parse','HEAD')!=record['mergedSha'] or git(root,'rev-parse','HEAD^{tree}')!=record['mergedTreeSha'] or git(root,'status','--porcelain','--untracked-files=no'):
        raise StageError('F05_BUNDLE_SOURCE_DRIFT')
    if output.exists() or output.is_symlink():raise StageError('F05_BUNDLE_OUTPUT_EXISTS')
    if record['mergedSha']==record['forkSha']:
        record['integrationBundle']=None
    else:
        # Export the real merge object and reachable upstream objects; fork
        # history is a prerequisite. Never recreate an approximate merge SHA.
        result=subprocess.run(['git','bundle','create',str(output),'HEAD','^'+record['forkSha']],cwd=root,capture_output=True,timeout=120)
        if result.returncode or not output.is_file() or output.stat().st_size>100_000_000:
            output.unlink(missing_ok=True);raise StageError('F05_BUNDLE_EXPORT_REFUSED')
        with output.open('rb') as stream:
            record['integrationBundle']={'name':output.name,'sha256':hashlib.file_digest(stream,'sha256').hexdigest(),'sizeBytes':output.stat().st_size,'prerequisite':record['forkSha']}
    report_path.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n',encoding='utf-8');return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('stage')
    s.add_argument('--channel', required=True, choices=('beta', 'stable'))
    s.add_argument('--upstream-sha', required=True)
    s.add_argument('--event-id', type=int, required=True)
    s.add_argument('--fork-sha', required=True)
    s.add_argument('--report', required=True, type=Path)
    f = sub.add_parser('finalize')
    f.add_argument('--report', required=True, type=Path)
    f.add_argument('--apk-dir', required=True, type=Path)
    b=sub.add_parser('export-bundle');b.add_argument('--report',required=True,type=Path);b.add_argument('--output',required=True,type=Path)
    args = p.parse_args(argv)
    try:
        if args.command=='export-bundle':return export_bundle(args.report,args.output,Path.cwd())
        if args.command == 'stage':
            return stage(Path.cwd(), args.channel, args.upstream_sha, args.event_id, args.fork_sha,
                         args.report, UpstreamClient(os.environ.get('GITHUB_TOKEN', '')))
        return finalize(args.report, args.apk_dir)
    except (StageError, ValueError, OSError) as error:
        print('BK_F05_REFUSED ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
