#!/usr/bin/env python3
"""Read-only source-pinned upstream event discovery for the BakaSU fork (F04).

This creates a candidate report ONLY. No merges, branch writes, build dispatch,
release publishing, device access, or Gradle execution occur here.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

UPSTREAM = 'Baka-SU/BakaSU'
FORK = 'Mikeyphw/BakaSU'
API_ROOT = f'https://api.github.com/repos/{UPSTREAM}'
BETA_WORKFLOW = 'build-manager.yml'
SHA_PATTERN = re.compile(r'^[0-9a-f]{40}$')
TAG_PATTERN = re.compile(r'^v[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
PAGE_SIZE = 100
MAX_PAGES = 4
DEFAULT_LOOKBACK_DAYS = 7
MAX_CANDIDATES = 120


class UpstreamDiscoveryError(RuntimeError):
    """A source or API ambiguity that must refuse automatic continuation."""


class JsonClient(Protocol):
    def get(self, route: str) -> Any: ...


class GitHubJsonClient:
    """GitHub API client restricted to one public upstream repository."""

    def __init__(self, token: str = '') -> None:
        self.token = token

    def get(self, route: str) -> Any:
        if not route.startswith('/') or route.startswith('//') or '\\' in route:
            raise UpstreamDiscoveryError('UNSAFE_UPSTREAM_API_ROUTE')
        request = Request(
            API_ROOT + route,
            headers={
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'BakaSU-fork-discovery',
                **({'Authorization': f'Bearer {self.token}'} if self.token else {}),
            },
        )
        try:
            with urlopen(request, timeout=20) as response:
                raw = response.read(6_000_001)
                if len(raw) > 6_000_000:
                    raise UpstreamDiscoveryError('UPSTREAM_RESPONSE_TOO_LARGE')
                return json.loads(raw)
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            # Never include response content or Authorization header in reports.
            status = getattr(exc, 'code', None)
            raise UpstreamDiscoveryError(f'UPSTREAM_REQUEST_FAILED status={status or "network"}') from None


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


def valid_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA_PATTERN.fullmatch(value) is not None


def validate_page(value: Any, key: str) -> list[dict[str, Any]]:
    if key:
        if not isinstance(value, dict) or not isinstance(value.get(key), list):
            raise UpstreamDiscoveryError(f'UPSTREAM_SCHEMA_MISMATCH field={key}')
        value = value[key]
    if not isinstance(value, list) or any(not isinstance(obj, dict) for obj in value):
        raise UpstreamDiscoveryError('UPSTREAM_LIST_SCHEMA_MISMATCH')
    if len(value) > PAGE_SIZE:
        raise UpstreamDiscoveryError('UPSTREAM_PAGE_OVERSIZED')
    return value


def paged(client: JsonClient, prefix: str, field: str, cutoff: datetime, date_key: str):
    """Stop once an entire page predates cutoff; refuse ambiguous truncation."""
    for page_no in range(1, MAX_PAGES + 1):
        route = f'{prefix}{"&" if "?" in prefix else "?"}per_page={PAGE_SIZE}&page={page_no}'
        items = validate_page(client.get(route), field)
        yield page_no, items
        if len(items) < PAGE_SIZE:
            return
        dates = [parse_time(x.get(date_key)) for x in items]
        # A missing date makes the traversal ambiguous, never silently stop.
        if dates and all(d is not None and d < cutoff for d in dates):
            return
    raise UpstreamDiscoveryError('UPSTREAM_PAGINATION_TRUNCATED')


def resolve_tag(client: JsonClient, tag: str) -> str:
    """Resolve lightweight or annotated Git tags to a real source commit."""
    ref = client.get('/git/ref/tags/' + quote(tag, safe=''))
    obj = ref.get('object') if isinstance(ref, dict) else None
    for _ in range(5):
        if not isinstance(obj, dict) or not valid_sha(obj.get('sha')):
            raise UpstreamDiscoveryError('UPSTREAM_TAG_REFERENCE_INVALID')
        if obj.get('type') == 'commit':
            return obj['sha']
        if obj.get('type') != 'tag':
            raise UpstreamDiscoveryError('UPSTREAM_TAG_TARGET_UNSUPPORTED')
        tagged = client.get('/git/tags/' + obj['sha'])
        obj = tagged.get('object') if isinstance(tagged, dict) else None
    raise UpstreamDiscoveryError('UPSTREAM_TAG_REFERENCE_TOO_DEEP')


def discover_beta(client: JsonClient, cutoff: datetime, now: datetime) -> tuple[list[dict[str, Any]], int]:
    results: dict[str, dict[str, Any]] = {}
    seen = 0
    prefix = '/actions/workflows/' + BETA_WORKFLOW + '/runs?branch=main&event=push'
    for _, runs in paged(client, prefix, 'workflow_runs', cutoff, 'created_at'):
        for run in runs:
            seen += 1
            created = parse_time(run.get('created_at'))
            if created is None or created < cutoff or created > now:
                continue
            if (run.get('head_branch') != 'main' or run.get('event') != 'push'
                    or run.get('conclusion') != 'success' or run.get('status') != 'completed'):
                continue
            source_repo = run.get('head_repository')
            if source_repo is not None and (not isinstance(source_repo, dict)
                                            or source_repo.get('full_name') != UPSTREAM):
                continue
            sha = run.get('head_sha')
            run_id = run.get('id')
            if not valid_sha(sha) or type(run_id) is not int or run_id <= 0:
                continue
            item = {
                'key': f'beta:{sha}', 'channel': 'beta', 'upstreamSha': sha,
                'upstreamRunId': run_id, 'eventAt': created.isoformat(),
                'upstreamUrl': f'https://github.com/{UPSTREAM}/actions/runs/{run_id}',
            }
            old = results.get(item['key'])
            if old is None or (item['eventAt'], item['upstreamRunId']) > (old['eventAt'], old['upstreamRunId']):
                results[item['key']] = item
    return list(results.values()), seen


def discover_stable(client: JsonClient, cutoff: datetime, now: datetime) -> tuple[list[dict[str, Any]], int]:
    results: dict[str, dict[str, Any]] = {}
    seen = 0
    for _, releases in paged(client, '/releases', '', cutoff, 'published_at'):
        for release in releases:
            seen += 1
            published = parse_time(release.get('published_at'))
            if published is None or published < cutoff or published > now or release.get('draft') or release.get('prerelease'):
                continue
            tag = release.get('tag_name')
            release_id = release.get('id')
            if not isinstance(tag, str) or TAG_PATTERN.fullmatch(tag) is None:
                continue
            if type(release_id) is not int or release_id <= 0:
                continue
            sha = resolve_tag(client, tag)
            item = {
                'key': f'stable:{tag}:{sha}', 'channel': 'stable', 'upstreamSha': sha,
                'upstreamTag': tag, 'upstreamReleaseId': release_id,
                'eventAt': published.isoformat(),
                'upstreamUrl': f'https://github.com/{UPSTREAM}/releases/tag/{quote(tag, safe="")}',
            }
            results[item['key']] = item
    return list(results.values()), seen


def build_report(client: JsonClient, now: datetime, lookback_days: int = DEFAULT_LOOKBACK_DAYS) -> dict[str, Any]:
    if now.tzinfo is None or not 1 <= lookback_days <= 30:
        raise ValueError('invalid UTC time or lookback window')
    now = now.astimezone(timezone.utc)
    cutoff = now - timedelta(days=lookback_days)
    beta, beta_seen = discover_beta(client, cutoff, now)
    stable, stable_seen = discover_stable(client, cutoff, now)
    combined = sorted(beta + stable, key=lambda item: (item['eventAt'], item['key']))
    if len(combined) > MAX_CANDIDATES:
        raise UpstreamDiscoveryError('UPSTREAM_CANDIDATE_QUEUE_OVERFLOW')
    return {
        'schemaVersion': 1,
        'mode': 'discovery-only',
        'upstreamRepository': UPSTREAM,
        'forkRepository': FORK,
        'checkedAt': now.isoformat(),
        'lookbackStart': cutoff.isoformat(),
        'betaRunsScanned': beta_seen,
        'releasesScanned': stable_seen,
        'candidates': combined,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('upstream-candidates.json'))
    parser.add_argument('--lookback-days', type=int, default=DEFAULT_LOOKBACK_DAYS)
    args = parser.parse_args(argv)
    try:
        report = build_report(GitHubJsonClient(os.environ.get('GITHUB_TOKEN', '')),
                              datetime.now(timezone.utc), args.lookback_days)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        print(f'BK_F04_DISCOVERY_PASS candidates={len(report["candidates"])} '
              f'beta_scanned={report["betaRunsScanned"]} releases_scanned={report["releasesScanned"]}')
        print(f'BK_F04_OUTPUT {args.output}')
        print('BK_F04_NO_BUILD_NO_RELEASE_NO_MUTATION')
        return 0
    except (UpstreamDiscoveryError, ValueError, OSError) as error:
        print(f'BK_F04_REFUSED {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
