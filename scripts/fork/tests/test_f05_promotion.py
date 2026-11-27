"""Git-object and artifact binding controls; no hosted build acceptance claim."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import event_journal as j
import promotion_plan as p
import release_lineage as lineage
import f05_source_build as build
from journal_cli import review
from journal_store import LocalJournal
from test_f05_event_journal import candidate, report as discovery_report, run, OLD, NOW


class PromotionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='f05-promotion-test-')
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.root = self.home / 'repo'
        self.root.mkdir()
        self.git('init', '-b', 'main')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@localhost')
        self.git('remote', 'add', 'origin', 'https://github.com/' + j.REPO)
        (self.root / 'modify.txt').write_text('old\n')
        (self.root / 'delete.txt').write_text('remove\n')
        self.git('add', '.')
        self.git('commit', '-m', 'base')
        self.fork = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-b', 'upstream')
        (self.root / 'modify.txt').write_text('new\n')
        (self.root / 'delete.txt').unlink()
        (self.root / 'add.txt').write_text('added\n')
        self.git('add', '-A')
        self.git('commit', '-m', 'upstream')
        self.upstream = self.git('rev-parse', 'HEAD')
        self.git('checkout', '-b', 'diagnostic', self.fork)
        result = build.integration(self.root, self.fork, self.upstream, fetch_url=str(self.root))
        self.report = dict(result, schemaVersion=1, mode='F05-unsigned-diagnostic-only', channel='beta', upstreamEventId=10, status='debug-build-validated', apkChecksums={'fixture.apk': 'a'*64})
        self.key = 'beta:' + self.upstream
        self.initial = j.initial(j.timestamp(OLD),100)
        self.discovered = j.ingest(self.initial,discovery_report(self.initial,candidate(source=self.upstream)),NOW)
        self.intent, _ = j.begin(self.discovered, self.key, self.fork)
        self.live = run(self.intent, self.key)
        self.state = j.observe(self.intent, self.key, [self.live])
        self.row = self.state['events'][self.key]
        self.report_path = self.home / 'f05-source-provenance.json'
        self.report_path.write_text(json.dumps(self.report))
        self.bundle = self.home / 'f05-integration.bundle'
        build.export_bundle(self.report_path, self.bundle, self.root)
        self.report = json.loads(self.report_path.read_text())
        self.artifact = self.home / 'promotion.zip'
        with zipfile.ZipFile(self.artifact, 'w') as z:
            z.write(self.report_path, self.report_path.name)
            z.write(self.bundle, self.bundle.name)
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.meta = dict(id=100, name='f05-promotion-31', workflow_run={'id':31,'head_sha':self.fork}, expired=False, digest='sha256:'+self.digest)
        self.git('checkout', 'main')
        self.store = LocalJournal(self.home / 'journal.json')
        self.store.initialize(self.initial)
        self.store.replace(self.initial,self.discovered)
        self.store.replace(self.discovered,self.intent)
        self.store.replace(self.intent,self.state)
        self.remote_main = self.fork

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True, text=True).stdout.strip()

    def request(self, route):
        if route == '/actions/runs/31': return self.live
        if route == '/actions/artifacts/100': return self.meta
        if route == '/git/ref/heads/main': return {'ref':'refs/heads/main','object':{'sha':self.remote_main}}
        if route == '/releases?per_page=100&page=1': return [{'id':1,'draft':False,'assets':[{'name':'BakaSU_v1_500-universal-release.apk'}]}]
        raise AssertionError(route)

    def test_bundle_import_and_exact_inventory(self):
        result = review(self.store, self, self.key, self.root, self.artifact, 100)
        self.assertEqual(result['post_tree'], self.report['mergedTreeSha'])
        self.assertEqual(result['artifactSha256'], self.digest)
        entries = {e['path']: e for e in result['entries']}
        self.assertEqual(set(entries), {'modify.txt','delete.txt','add.txt'})
        self.assertEqual(entries['modify.txt']['sha256'], hashlib.sha256(b'new\n').hexdigest())
        self.assertIsNone(entries['add.txt']['source_sha256'])
        self.assertIsNone(entries['delete.txt']['sha256'])
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.fork)
        self.assertEqual(self.store.read(), self.state)

    def test_wrong_report_tree_and_stale_base_rejected(self):
        for report, base in ((dict(self.report, mergedTreeSha='f'*40), self.fork), (self.report, self.upstream), (dict(self.report, changedPaths=[]), self.fork)):
            with self.subTest(report=report, base=base), self.assertRaises(j.JournalError):
                p.inventory(self.root, self.row, report, base)

    def test_provider_artifact_identity_and_digest(self):
        original = copy.deepcopy(self.meta)
        for changes in ({'expired':True}, {'digest':'sha256:'+'f'*64}, {'workflow_run':{'id':32,'head_sha':self.fork}}, {'name':'wrong'}):
            self.meta = dict(original, **changes)
            with self.subTest(changes=changes), self.assertRaises(j.JournalError):
                p.verify_artifact(self, self.row, self.artifact, 100)
        self.meta = original
        report, bundle, digest = p.verify_artifact(self, self.row, self.artifact, 100)
        self.assertEqual(report, self.report)
        self.assertEqual(bundle, self.bundle.read_bytes())
        self.assertEqual(digest, self.digest)

    def test_reserve_after_actual_exact_tree_main_promotion(self):
        with self.assertRaisesRegex(j.JournalError,'MAIN_ANCESTOR'):
            review(self.store,self,self.key,self.root,self.artifact,100,self.report['mergedSha'])
        commit = self.git('commit-tree', self.report['mergedTreeSha'], '-p', self.fork, '-m', 'reviewed native tree')
        self.git('reset','--hard',commit)  # disposable fixture only
        self.remote_main = commit
        reserved = review(self.store,self,self.key,self.root,self.artifact,100,commit)
        self.assertEqual(reserved['versionCode'], 501)
        self.assertEqual(reserved['status'], 'RESERVED_NOT_SIGNED_NOT_PUBLISHED')
        self.assertEqual(review(self.store,self,self.key,self.root,self.artifact,100,commit), reserved)

    def test_journal_export_binds_actual_reserved_tree_and_provider_identity(self):
        with self.assertRaisesRegex(lineage.Refused,'RESERVATION_MISSING'):
            lineage.export_reservation(self.store.read(),self.key)
        commit = self.git('commit-tree', self.report['mergedTreeSha'], '-p', self.fork, '-m', 'reviewed native tree')
        self.git('reset','--hard',commit)
        self.remote_main = commit
        review(self.store,self,self.key,self.root,self.artifact,100,commit)
        state=self.store.read()
        row=lineage.export_reservation(state,self.key)
        self.assertEqual(row['sourceCommit'],commit)
        self.assertEqual(row['sourceTree'],self.report['mergedTreeSha'])
        self.assertEqual(row['diagnosticArtifactSha256'],self.digest)
        self.assertEqual(row['versionCode'],501)
        self.assertEqual(lineage.export_reservation(self.store.read(),self.key),row)
        lineage.committed_source(self.root,row,commit)
        self.assertEqual(self.store.read(),state)
        with self.assertRaises(lineage.Refused):
            lineage.validate_reservation(dict(row,versionCode=502))

    def test_wrong_release_asset_fails_closed(self):
        class Unknown:
            def request(self, route):
                return [{'id':1,'draft':False,'assets':[{'name':'unknown.apk'}]}]
        with self.assertRaisesRegex(j.JournalError,'UNRECOGNIZED'):
            p.published_version_floor(Unknown())

    def test_bundle_refuses_wrong_checkout(self):
        with self.assertRaisesRegex(build.StageError, 'SOURCE_DRIFT'):
            build.export_bundle(self.report_path,self.home/'new.bundle',self.root)


if __name__ == '__main__':
    unittest.main()
