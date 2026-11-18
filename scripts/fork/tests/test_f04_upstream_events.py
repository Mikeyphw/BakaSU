"""F04 read-only upstream discovery: deterministic event and failure contracts."""
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'upstream_events.py'
spec = importlib.util.spec_from_file_location('upstream_events', MODULE)
discovery = importlib.util.module_from_spec(spec)
assert spec and spec.loader
import sys
sys.modules[spec.name] = discovery
spec.loader.exec_module(discovery)

NOW = datetime(2026, 11, 15, 20, 0, tzinfo=timezone.utc)
RECENT = '2026-11-15T18:00:00Z'
OLD = '2026-11-01T18:00:00Z'
A = 'a' * 40
B = 'b' * 40
C = 'c' * 40
D = 'd' * 40


def beta(run_id=25, sha=A, when=RECENT, **changes):
    return dict(id=run_id, head_sha=sha, created_at=when, head_branch='main',
                event='push', conclusion='success', status='completed',
                head_repository={'full_name': discovery.UPSTREAM}, **changes)


def release(release_id=42, tag='v9.4.0', when=RECENT, **changes):
    return dict(id=release_id, tag_name=tag, published_at=when,
                draft=False, prerelease=False, **changes)


class Fake:
    def __init__(self, beta_items=None, stable_items=None, tag_resolutions=None):
        self.beta_items = beta_items or []
        self.stable_items = stable_items or []
        self.tag_resolutions = tag_resolutions or {'v9.4.0': {'type': 'commit', 'sha': B}}
        self.calls = []

    def get(self, route):
        self.calls.append(route)
        if route.startswith('/actions/workflows/'):
            return {'workflow_runs': self.beta_items}
        if route.startswith('/releases?'):
            return self.stable_items
        if route.startswith('/git/ref/tags/'):
            tag = route.split('/')[-1]
            if tag not in self.tag_resolutions:
                raise discovery.UpstreamDiscoveryError('TAG_NOT_FOUND')
            return {'object': self.tag_resolutions[tag]}
        if route.startswith('/git/tags/'):
            return {'object': {'type': 'commit', 'sha': B}}
        raise AssertionError('unexpected API route: ' + route)


class DiscoveryContracts(unittest.TestCase):
    def test_beta_and_stable_source_sha_and_sorted_report(self):
        c = Fake([beta()], [release()])
        report = discovery.build_report(c, NOW)
        self.assertEqual([e['channel'] for e in report['candidates']], ['beta', 'stable'])
        self.assertEqual([e['upstreamSha'] for e in report['candidates']], [A, B])
        self.assertEqual(report['mode'], 'discovery-only')
        self.assertEqual(report['forkRepository'], 'Mikeyphw/BakaSU')
        self.assertNotIn('token', repr(report).lower())

    def test_beta_rejects_wrong_event_status_or_source(self):
        invalid = []
        for item in [dict(beta(1), event='pull_request'),
                     dict(beta(2), status='in_progress'),
                     dict(beta(3), conclusion='failure'),
                     dict(beta(4), head_branch='dev'),
                     dict(beta(5), head_repository={'full_name': 'other/repo'}),
                     dict(beta(6), head_sha='invalid'),
                     beta(7, when=OLD)]:
            invalid.append(item)
        report = discovery.build_report(Fake(invalid, []), NOW)
        self.assertEqual(report['candidates'], [])

    def test_beta_deduplicates_reruns_by_source_sha(self):
        report = discovery.build_report(Fake([beta(21), beta(22)], []), NOW)
        self.assertEqual(len(report['candidates']), 1)
        self.assertEqual(report['candidates'][0]['upstreamRunId'], 22)

    def test_release_draft_prerelease_and_older_excluded(self):
        events = [dict(release(43), draft=True), dict(release(44), prerelease=True),
                  release(45, when=OLD), release(46, tag='invalid'), release()]
        report = discovery.build_report(Fake([], events), NOW)
        self.assertEqual(len(report['candidates']), 1)
        self.assertEqual(report['candidates'][0]['upstreamTag'], 'v9.4.0')

    def test_annotated_tag_is_followed(self):
        c = Fake([], [release()], {'v9.4.0': {'type': 'tag', 'sha': C}})
        report = discovery.build_report(c, NOW)
        self.assertEqual(report['candidates'][0]['upstreamSha'], B)
        self.assertIn('/git/tags/' + C, c.calls)

    def test_missing_or_invalid_tag_ref_fails_closed(self):
        with self.assertRaises(discovery.UpstreamDiscoveryError):
            discovery.build_report(Fake([], [release()], {'v9.4.0': {'type': 'blob', 'sha': C}}), NOW)
        with self.assertRaises(discovery.UpstreamDiscoveryError):
            discovery.build_report(Fake([], [release()], {} if False else {'v9.4.0': {'type': 'tag', 'sha': 'bad'}}), NOW)

    def test_invalid_datetime_or_lookback_fails(self):
        self.assertIsNone(discovery.parse_time('not a date'))
        self.assertIsNone(discovery.parse_time('2026-11-15T19:00:00'))
        with self.assertRaises(ValueError):
            discovery.build_report(Fake(), NOW, 31)
        with self.assertRaises(ValueError):
            discovery.build_report(Fake(), NOW.replace(tzinfo=None))

    def test_truncated_page_refused(self):
        c = Fake([beta(i + 1, sha=f'{i:040x}') for i in range(100)], [])
        # Exactly 100 newer source runs on every page must refuse missing history.
        with self.assertRaisesRegex(discovery.UpstreamDiscoveryError, 'PAGINATION_TRUNCATED'):
            discovery.build_report(c, NOW)

    def test_malformed_api_page_fails_closed(self):
        class Malformed:
            def get(self, route): return {'oops': []}
        with self.assertRaises(discovery.UpstreamDiscoveryError):
            discovery.build_report(Malformed(), NOW)

    def test_future_events_not_accepted(self):
        report = discovery.build_report(Fake([beta(1, when='2026-12-01T00:00:00Z')], []), NOW)
        # Candidate dates must never be in the future.
        self.assertEqual(report['candidates'], [])

    def test_no_api_network_or_writes_in_fake_tests(self):
        c = Fake()
        self.assertEqual(discovery.build_report(c, NOW)['candidates'], [])
        self.assertTrue(all(route.startswith('/') for route in c.calls))


if __name__ == '__main__':
    unittest.main()
