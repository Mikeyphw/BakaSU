#!/usr/bin/env python3
"""F05: at-most-once (per observed workflow event) upstream candidate dispatch.

Uses the F04 output; validates against runs from the fork before dispatch. On
API ambiguity it refuses to publish instructions or skip unknown state.
All sources are independently verified again in the target build workflow.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

FORK = 'Mikeyphw/BakaSU'
UPSTREAM = 'Baka-SU/BakaSU'
WORKFLOW = 'fork-source-build.yml'
FORK_SHA = re.compile(r'^[0-9a-f]{40}$')
MAX_RUN_PAGES = 5
MAX_DISPATCH = 4


class DispatchError(RuntimeError):
    pass


def run_title(channel: str, upstream_sha: str, fork_sha: str) -> str:
    return f'F05/{channel}/{upstream_sha}/{fork_sha}'


def eligible_candidates(report: dict) -> list[dict]:
    if not isinstance(report, dict) or report.get('schemaVersion') != 1 or report.get('mode') != 'discovery-only':
        raise DispatchError('INVALID_DISCOVERY_REPORT')
    if report.get('upstreamRepository') != UPSTREAM or report.get('forkRepository') != FORK:
        raise DispatchError('REPORT_REPOSITORY_MISMATCH')
    candidates = report.get('candidates')
    if not isinstance(candidates, list) or len(candidates) > 120:
        raise DispatchError('CANDIDATE_LIST_INVALID')
    validated = []
    seen = set()
    for item in candidates:
        if not isinstance(item, dict):
            raise DispatchError('CANDIDATE_INVALID')
        channel, sha, key = item.get('channel'), item.get('upstreamSha'), item.get('key')
        if channel not in ('beta', 'stable') or not isinstance(sha, str) or not FORK_SHA.fullmatch(sha):
            raise DispatchError('CANDIDATE_PROVENANCE_INVALID')
        ident = item.get('upstreamRunId') if channel == 'beta' else item.get('upstreamReleaseId')
        if type(ident) is not int or ident <= 0:
            raise DispatchError('CANDIDATE_EVENT_ID_INVALID')
        if not isinstance(key, str) or not key.startswith(channel + ':'):
            raise DispatchError('CANDIDATE_KEY_INVALID')
        if (channel, sha) in seen:
            raise DispatchError('DUPLICATE_SHA_CHANNEL_IN_REPORT')
        seen.add((channel, sha))
        validated.append({'channel': channel, 'upstreamSha': sha, 'eventId': ident, 'key': key})
    # Stable events receive priority; oldest first within each channel to
    # prevent silently skipping a long set of missed releases.
    return sorted(validated, key=lambda c: (c['channel'] != 'stable', c['key']))


class Client:
    def __init__(self, token: str):
        if not token:
            raise DispatchError('NO_GITHUB_TOKEN')
        self.token = token

    def request(self, route: str, data: dict | None = None):
        if not route.startswith('/') or route.startswith('//') or '\\' in route:
            raise DispatchError('UNSAFE_FORK_API_PATH')
        body = None if data is None else json.dumps(data).encode('utf-8')
        req = Request(
            'https://api.github.com/repos/' + FORK + route,
            data=body,
            headers={
                'Authorization': 'Bearer ' + self.token,
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'BakaSU-fork-f05-dispatch',
                **({'Content-Type': 'application/json'} if body else {}),
            },
            method='POST' if body else 'GET',
        )
        try:
            with urlopen(req, timeout=25) as res:
                if body is not None:
                    if res.status != 204:
                        raise DispatchError('DISPATCH_UNEXPECTED_STATUS')
                    return None
                raw = res.read(6_000_001)
                if len(raw) > 6_000_000:
                    raise DispatchError('DISPATCH_RESPONSE_TOO_LARGE')
                return json.loads(raw)
        except (HTTPError, URLError, TimeoutError, ValueError) as err:
            raise DispatchError(f'GITHUB_API_FAILED status={getattr(err, "code", "network")}') from None

    def recent_builds(self, earliest_iso: str) -> list[dict]:
        all_runs = []
        total = None
        for page in range(1, MAX_RUN_PAGES + 1):
            query = urlencode({'event': 'workflow_dispatch', 'per_page': 100,
                               'created': '>=' + earliest_iso, 'page': page})
            response = self.request('/actions/workflows/' + WORKFLOW + '/runs?' + query)
            if not isinstance(response, dict) or not isinstance(response.get('workflow_runs'), list):
                raise DispatchError('RUNS_SCHEMA_INVALID')
            if type(response.get('total_count')) is not int or response['total_count'] < 0:
                raise DispatchError('RUN_COUNT_INVALID')
            if total is None:
                total = response['total_count']
            if response['total_count'] != total:
                raise DispatchError('RUN_COUNT_CHANGED_DURING_SCAN')
            runs = response['workflow_runs']
            if len(runs) > 100 or any(not isinstance(r, dict) for r in runs):
                raise DispatchError('RUN_PAGE_INVALID')
            all_runs.extend(runs)
            if len(all_runs) >= total:
                return all_runs
            if not runs:
                raise DispatchError('RUN_PAGE_INCOMPLETE')
        raise DispatchError('RUN_HISTORY_TRUNCATED')

    def dispatch(self, item: dict, fork_sha: str):
        self.request('/actions/workflows/' + WORKFLOW + '/dispatches', {
            'ref': 'main',
            'inputs': {
                'channel': item['channel'], 'upstream_sha': item['upstreamSha'],
                'upstream_event_id': str(item['eventId']), 'fork_sha': fork_sha,
            },
        })


def plan(report: dict, fork_sha: str, runs: list[dict]) -> dict:
    if not isinstance(fork_sha, str) or not FORK_SHA.fullmatch(fork_sha):
        raise DispatchError('FORK_SOURCE_SHA_INVALID')
    # If workflow runs are ambiguous or missing essential fields, NEVER guess.
    known = set()
    for r in runs:
        if r.get('head_branch') != 'main':
            continue
        title = r.get('display_title')
        if not isinstance(title, str):
            raise DispatchError('RUN_TITLE_ABSENT')
        known.add(title)
    candidates = eligible_candidates(report)
    pending, duplicate = [], []
    for item in candidates:
        title = run_title(item['channel'], item['upstreamSha'], fork_sha)
        if title in known:
            duplicate.append(item['key'])
        elif len(pending) < MAX_DISPATCH:
            pending.append(item)
    return {'pending': pending, 'alreadyObserved': duplicate,
            'pendingBeyondLimit': max(0, len(candidates) - len(duplicate) - len(pending))}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(argv)
    ledger = {'schemaVersion': 1, 'mode': 'F05-diagnostic-build-only', 'dispatched': [], 'blocked': []}
    try:
        fork_sha = os.environ.get('FORK_SHA', '')
        if os.environ.get('GITHUB_REPOSITORY') != FORK or os.environ.get('GITHUB_REF') != 'refs/heads/main':
            raise DispatchError('ONLY_DEFAULT_FORK_BRANCH_MAY_DISPATCH')
        if not FORK_SHA.fullmatch(fork_sha):
            raise DispatchError('INVALID_FORK_SHA')
        report = json.loads(args.report.read_text(encoding='utf-8'))
        client = Client(os.environ.get('GITHUB_TOKEN', ''))
        checked = datetime.fromisoformat(report['checkedAt'])
        if checked.tzinfo is None:
            raise DispatchError('REPORT_TIME_INVALID')
        since = (checked.astimezone(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ')
        actions = plan(report, fork_sha, client.recent_builds(since))
        ledger.update({'forkSha': fork_sha, 'alreadyObserved': actions['alreadyObserved'],
                       'pendingBeyondLimit': actions['pendingBeyondLimit']})
        for item in actions['pending']:
            client.dispatch(item, fork_sha)
            ledger['dispatched'].append(item)
            print('BK_F05_DISPATCH_ACCEPTED ' + run_title(item['channel'], item['upstreamSha'], fork_sha))
        print(f'BK_F05_DISPATCH_PASS dispatched={len(ledger["dispatched"])}'
              f' duplicates={len(actions["alreadyObserved"])}'
              f' backlogged={actions["pendingBeyondLimit"]}')
        return 0
    except (DispatchError, ValueError, OSError, KeyError, TypeError) as error:
        ledger['blocked'].append(str(error))
        print('BK_F05_DISPATCH_REFUSED ' + str(error), file=sys.stderr)
        return 2
    finally:
        args.output.write_text(json.dumps(ledger, indent=2, sort_keys=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    sys.exit(main())
