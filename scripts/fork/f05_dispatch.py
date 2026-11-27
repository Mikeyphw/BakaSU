#!/usr/bin/env python3
"""Restricted F05 provider interface. Durable journal_cli owns dispatch intent.

No executable legacy dispatch path is retained: the seven-day scan was not a
persistent at-most-once journal.
"""
from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

FORK = 'Mikeyphw/BakaSU'
UPSTREAM = 'Baka-SU/BakaSU'
WORKFLOW = 'fork-source-build.yml'
MAX_RUN_PAGES = 5
MAX_DISPATCH = 4

class DispatchError(RuntimeError):
    pass

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
        observed_ids = set()
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
            for run in runs:
                rid = run.get('id')
                if type(rid) is not int or rid <= 0 or rid in observed_ids:
                    raise DispatchError('RUN_IDENTITY_AMBIGUOUS')
                observed_ids.add(rid)
            all_runs.extend(runs)
            if len(all_runs) > total:
                raise DispatchError('RUN_COUNT_CHANGED_DURING_SCAN')
            if len(all_runs) == total:
                return all_runs
            if not runs:
                raise DispatchError('RUN_PAGE_INCOMPLETE')
        raise DispatchError('RUN_HISTORY_TRUNCATED')
