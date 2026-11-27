"""F05 in-memory source-qualification and dedup tests; no network or device."""
from pathlib import Path
import importlib.util
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dispatch = load('f05_dispatch')
build = load('f05_source_build')
A, B, C = 'a' * 40, 'b' * 40, 'c' * 40


class FakeUpstream:
    def __init__(self, routes):
        self.routes = routes
    def get(self, route):
        return self.routes[route]


class F05SourceTests(unittest.TestCase):
    def test_beta_requires_exact_verified_run_and_upstream(self):
        data = {'head_sha': A, 'head_branch': 'main', 'event': 'push',
                'status': 'completed', 'conclusion': 'success',
                'head_repository': {'full_name': build.UPSTREAM},
                'path': '.github/workflows/build-manager.yml'}
        self.assertEqual(build.verify_event(FakeUpstream({'/actions/runs/15': data}), 'beta', A, 15)['upstreamSha'], A)
        for bad in [dict(data, conclusion='failure'), dict(data, event='pull_request'),
                    dict(data, head_sha=B), dict(data, head_repository={'full_name':'someone/fake'}),
                    dict(data, path='other-workflow.yml')]:
            with self.assertRaises(build.StageError):
                build.verify_event(FakeUpstream({'/actions/runs/15': bad}), 'beta', A, 15)

    def test_stable_release_validates_tag_source(self):
        routes = {'/releases/23': {'draft': False, 'prerelease': False,
                                  'tag_name': 'v3.0', 'published_at': '2026-11-15T00:00:00Z'},
                  '/git/ref/tags/v3.0': {'object': {'type': 'commit', 'sha': A}}}
        self.assertEqual(build.verify_event(FakeUpstream(routes), 'stable', A, 23)['upstreamTag'], 'v3.0')
        with self.assertRaises(build.StageError):
            build.verify_event(FakeUpstream(routes), 'stable', B, 23)
        routes['/releases/23']['draft'] = True
        with self.assertRaises(build.StageError):
            build.verify_event(FakeUpstream(routes), 'stable', A, 23)

    def test_annotated_tags_and_invalid_targets(self):
        client = FakeUpstream({'/git/ref/tags/v3.0': {'object': {'type': 'tag', 'sha': B}},
                               '/git/tags/' + B: {'object': {'type': 'commit', 'sha': A}}})
        self.assertEqual(build.resolve_tag(client, 'v3.0'), A)
        with self.assertRaises(build.StageError):
            build.resolve_tag(client, '../invalid')

    def test_no_mutating_repo_or_device_operations_in_modules(self):
        code = (SCRIPT / 'f05_source_build.py').read_text()
        self.assertNotIn('git push', code)
        self.assertNotIn('su -c ', code)
        self.assertNotIn('gradlew ', code)
        self.assertNotIn('softprops/action-gh-release', code)


if __name__ == '__main__':
    unittest.main()

# Isolated Git tests use new temporary repositories; no real fork or network.
class F05IntegrationTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        import subprocess
        self.temp = tempfile.TemporaryDirectory(prefix='bk-f05-git-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        def git(*args):
            p = subprocess.run(['git', *args], cwd=self.root, text=True,
                               capture_output=True)
            if p.returncode:
                raise AssertionError(str(args) + ': ' + p.stderr)
            return p.stdout.strip()
        self.git = git
        git('init', '-b', 'main')
        git('config', 'user.email', 'f05-test@localhost')
        git('config', 'user.name', 'F05 Test')
        (self.root / 'base.txt').write_text('original\n')
        git('add', 'base.txt'); git('commit', '-m', 'base')
        self.base = git('rev-parse', 'HEAD')
        git('checkout', '-b', 'upstream')
        (self.root / 'upstream.txt').write_text('upstream-change\n')
        git('add', 'upstream.txt'); git('commit', '-m', 'upstream')
        self.upstream = git('rev-parse', 'HEAD')
        git('checkout', 'main')
        (self.root / 'fork.txt').write_text('fork-change\n')
        git('add', 'fork.txt'); git('commit', '-m', 'fork')
        self.fork = git('rev-parse', 'HEAD')

    def test_clean_merge_preserves_both_sources(self):
        result = build.integration(self.root, self.fork, self.upstream, fetch_url=str(self.root))
        self.assertEqual(result['integrationMode'], 'merge-commit')
        self.assertEqual(result['forkSha'], self.fork)
        self.assertEqual(result['upstreamSha'], self.upstream)
        self.assertTrue((self.root / 'upstream.txt').is_file())
        self.assertTrue((self.root / 'fork.txt').is_file())
        self.assertEqual(self.git('status', '--porcelain=v1'), '')

    def test_already_integrated_upstream_does_not_mutate(self):
        result = build.integration(self.root, self.fork, self.base, fetch_url=str(self.root))
        self.assertEqual(result['integrationMode'], 'already-ancestor')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.fork)

    def test_conflicting_upstream_merge_aborts_cleanly(self):
        self.git('checkout', 'upstream')
        (self.root / 'base.txt').write_text('upstream-conflict\n')
        self.git('add', 'base.txt'); self.git('commit', '-m', 'upstream conflict')
        upstream = self.git('rev-parse', 'HEAD')
        self.git('checkout', 'main')
        (self.root / 'base.txt').write_text('fork-conflict\n')
        self.git('add', 'base.txt'); self.git('commit', '-m', 'fork conflict')
        fork = self.git('rev-parse', 'HEAD')
        with self.assertRaisesRegex(build.StageError, 'UPSTREAM_MERGE_CONFLICT'):
            build.integration(self.root, fork, upstream, fetch_url=str(self.root))
        self.assertEqual(self.git('rev-parse', 'HEAD'), fork)
        self.assertEqual(self.git('status', '--porcelain=v1'), '')
