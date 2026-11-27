"""Actual durable journal, provider replay and version allocation tests."""
from datetime import datetime,timedelta,timezone
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import event_journal as j
from journal_store import LocalJournal
from journal_cli import dispatch_pending, reconcile
from f05_dispatch import Client, DispatchError
from upstream_events import build_window_report, UpstreamDiscoveryError

A,B,C,D = [ch*40 for ch in 'abcd']
NOW=datetime(2026,11,27,12,tzinfo=timezone.utc)
OLD=NOW-timedelta(days=22)

def candidate(channel='beta',source=A,ident=10,when=OLD,tag='v1.0'):
    key=f'beta:{source}' if channel=='beta' else f'stable:{tag}:{source}'
    return dict(key=key,channel=channel,upstreamSha=source,eventAt=j.timestamp(when),**({'upstreamRunId':ident} if channel=='beta' else {'upstreamReleaseId':ident,'upstreamTag':tag}))

def report(state,*rows,now=NOW):
    start,end=j.discovery_window(state,now)
    return dict(schemaVersion=1,mode='discovery-only',forkRepository=j.REPO,upstreamRepository=j.UPSTREAM,checkedAt=j.timestamp(end),lookbackStart=j.timestamp(start),candidates=list(rows),unsettledBeta=[])

def seeded(*rows):
    state=j.initial(j.timestamp(OLD),100)
    return j.ingest(state,report(state,*rows),NOW)

def run(state,key,ident=31,conclusion='success',status='completed'):
    row=state['events'][key];a=row['attempts'][-1]
    return dict(id=ident,display_title=j.title(row['event'],a),event='workflow_dispatch',head_branch='main',head_sha=a['forkSha'],head_repository={'full_name':j.REPO},path='.github/workflows/fork-source-build.yml',status=status,conclusion=conclusion)

class JournalTests(unittest.TestCase):
    def test_long_outage_advances_no_more_than_one_window(self):
        state=seeded(candidate())
        self.assertEqual(j.utc(state['checkpoint']),OLD+timedelta(days=7))
        state=j.ingest(state,report(state),NOW)
        self.assertEqual(j.utc(state['checkpoint']),OLD+timedelta(days=14))
        self.assertIn('beta:'+A,state['events'])

    def test_long_running_beta_prevents_cursor_skip(self):
        s=j.initial(j.timestamp(OLD),0);r=report(s)
        when=OLD+timedelta(minutes=30);r['unsettledBeta']=[{'upstreamRunId':77,'eventAt':j.timestamp(when)}]
        next_state=j.ingest(s,r,NOW);self.assertEqual(j.utc(next_state['checkpoint']),when)

    def test_exact_window_and_clock_regression(self):
        s=j.initial(j.timestamp(OLD),0)
        r=report(s);r['checkedAt']=j.timestamp(NOW)
        with self.assertRaisesRegex(j.JournalError,'WINDOW'):j.ingest(s,r,NOW)
        with self.assertRaisesRegex(j.JournalError,'CLOCK'):j.discovery_window(s,OLD-timedelta(seconds=1))

    def test_duplicates_and_moved_stable_tag_refuse(self):
        s=j.initial(j.timestamp(OLD),0);a=candidate('stable',A)
        with self.assertRaisesRegex(j.JournalError,'DUPLICATE'):j.ingest(s,report(s,a,a),NOW)
        with self.assertRaisesRegex(j.JournalError,'TAG_MOVED'):j.ingest(s,report(s,a,candidate('stable',B,11)),NOW)

    def test_event_keys_and_time_fail_closed(self):
        s=j.initial(j.timestamp(OLD),0)
        for row in (dict(candidate(),key='beta:wrong'),candidate(when=NOW),dict(candidate(),upstreamRunId=True)):
            with self.subTest(row=row),self.assertRaises(j.JournalError):j.ingest(s,report(s,row),NOW)

    def test_oldest_stable_first_and_global_attempt_limit(self):
        s=seeded(candidate('beta'),candidate('stable',B,11))
        self.assertEqual(j.pending(s,C),['stable:v1.0:'+B,'beta:'+A])
        k='beta:'+A
        for index,fork in enumerate((B,C,D)):
            s,_=j.begin(s,k,fork);s=j.observe(s,k,[run(s,k,ident=31+index,conclusion='failure')])
            self.assertNotIn(k,j.pending(s,fork))
        self.assertNotIn(k,j.pending(s,A))

    def test_unknown_outcome_never_replayed(self):
        s=seeded(candidate());k='beta:'+A;s,_=j.begin(s,k,B)
        self.assertEqual(j.observe(s,k,[]),s)
        self.assertNotIn(k,j.pending(s,C))
        with self.assertRaises(j.JournalError):j.begin(s,k,C)

    def test_wrong_run_identity_and_duplicate_match(self):
        s=seeded(candidate());k='beta:'+A;s,_=j.begin(s,k,B);good=run(s,k)
        for bad in (dict(good,head_sha=C),dict(good,head_repository={'full_name':'other/repo'}),dict(good,path='other.yml'),dict(good,id=True)):
            with self.subTest(bad=bad),self.assertRaises(j.JournalError):j.observe(s,k,[bad])
        with self.assertRaisesRegex(j.JournalError,'AMBIGUOUS'):j.observe(s,k,[good,good])

    def test_observe_then_finish_no_terminal_regression(self):
        s=seeded(candidate());k='beta:'+A;s,_=j.begin(s,k,B)
        s=j.observe(s,k,[run(s,k,conclusion=None,status='in_progress')]);self.assertEqual(s['events'][k]['attempts'][-1]['state'],'observed')
        s=j.observe(s,k,[run(s,k)]);self.assertEqual(s['events'][k]['attempts'][-1]['state'],'qualified')
        self.assertEqual(j.observe(s,k,[run(s,k)]),s)
        with self.assertRaises(j.JournalError):j.observe(s,k,[run(s,k,conclusion='failure')])

    def test_legacy_run_is_adopted_without_new_attempt(self):
        s=seeded(candidate());k='beta:'+A;draft,_=j.begin(s,k,B)
        draft['events'][k]['attempts'][-1]['legacy']=True
        after=j.adopt_legacy(s,k,B,[run(draft,k)])
        self.assertEqual(after['revision'],s['revision']+1)
        self.assertTrue(after['events'][k]['attempts'][0]['legacy'])
        self.assertNotIn(k,j.pending(after,C))

    def test_global_monotonic_allocator_across_channels(self):
        s=seeded(candidate(),candidate('stable',B,11));keys=['beta:'+A,'stable:v1.0:'+B]
        for i,key in enumerate(keys):
            s,_=j.begin(s,key,C);s=j.observe(s,key,[run(s,key,ident=31+i)])
        p={'commit':C,'tree':D,'diagnosticTree':D,'diagnosticRunId':31,'diagnosticArtifactId':77,'diagnosticArtifactSha256':'a'*64}
        s,n=j.reserve(s,keys[0],p,200);self.assertEqual(n,201)
        self.assertEqual(j.reserve(s,keys[0],p,200),(s,201))
        q=dict(p,commit=B,diagnosticRunId=32)
        s,n=j.reserve(s,keys[1],q,200);self.assertEqual(n,202)
        with self.assertRaises(j.JournalError):j.reserve(s,keys[0],p,201)
        with self.assertRaises(j.JournalError):j.reserve(s,keys[0],dict(p,commit=A),200)

    def test_exhaustion_and_mismatched_promotion(self):
        s=seeded(candidate());k='beta:'+A;s,_=j.begin(s,k,B);s=j.observe(s,k,[run(s,k)])
        p=dict(commit=C,tree=D,diagnosticTree=D,diagnosticRunId=31,diagnosticArtifactId=77,diagnosticArtifactSha256='a'*64)
        with self.assertRaisesRegex(j.JournalError,'SPACE_EXHAUSTED'):j.reserve(s,k,p,j.MAX_VERSION)
        with self.assertRaises(j.JournalError):j.reserve(s,k,dict(p,diagnosticTree=A),0)

    def test_strict_json_rejects_duplicate_and_nonfinite(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
            with self.assertRaises(j.JournalError):j.strict_json(raw)

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'journal.json';self.store=LocalJournal(self.path)
        self.state=j.initial(j.timestamp(OLD),0);self.store.initialize(self.state)

    def test_fresh_process_reopen_and_stale_writer(self):
        new=j.ingest(self.state,report(self.state,candidate()),NOW)
        self.store.replace(self.state,new)
        other=LocalJournal(self.path);self.assertEqual(other.read(),new)
        with self.assertRaisesRegex(j.JournalError,'CAS_MISMATCH'):other.replace(self.state,new)
        with self.assertRaisesRegex(j.JournalError,'ALREADY_EXISTS'):other.initialize(self.state)

    def test_atomic_failure_preserves_old_checkpoint(self):
        new=j.ingest(self.state,report(self.state,candidate()),NOW)
        with patch('journal_store.os.replace',side_effect=OSError('injected')):
            with self.assertRaises(OSError):self.store.replace(self.state,new)
        self.assertEqual(self.store.read(),self.state)
        self.assertFalse(list(self.path.parent.glob('.journal-*')))

    def test_symlink_and_permissions_refused(self):
        target=self.path.parent/'target';target.write_bytes(self.path.read_bytes());self.path.unlink();self.path.symlink_to(target)
        with self.assertRaises(OSError):self.store.read()
        self.path.unlink();self.path.write_bytes(target.read_bytes());self.path.chmod(0o644)
        with self.assertRaisesRegex(j.JournalError,'NOT_PRIVATE'):self.store.read()

    def test_history_removal_rejected(self):
        new=j.ingest(self.state,report(self.state,candidate()),NOW);self.store.replace(self.state,new)
        changed=copy.deepcopy(new);changed['revision']+=1;changed['events'].clear()
        with self.assertRaisesRegex(j.JournalError,'HISTORY_REMOVED'):self.store.replace(new,changed)

    def test_dispatch_intent_survives_ambiguous_remote_result(self):
        s=j.ingest(self.state,report(self.state,candidate()),NOW);self.store.replace(self.state,s)
        class Provider:
            posts=0
            def recent_builds(self,_):return []
            def request(provider,route,data=None):
                if data is not None:
                    provider.posts+=1
                    observed=self.store.read()['events']['beta:'+A]['attempts'][-1]
                    self.assertEqual(observed['state'],'intent');self.assertEqual(data['inputs']['journal_attempt'],observed['intentId'])
                    raise DispatchError('injected ambiguous POST')
                return {'ref':'refs/heads/main','object':{'sha':B}}
        c=Provider()
        with self.assertRaises(DispatchError):dispatch_pending(self.store,c,B)
        self.assertEqual(c.posts,1)
        self.assertEqual(dispatch_pending(LocalJournal(self.path),c,B),[])
        self.assertEqual(c.posts,1)

    def test_dispatch_reconciles_existing_legacy_run(self):
        s=j.ingest(self.state,report(self.state,candidate()),NOW);self.store.replace(self.state,s);draft,_=j.begin(s,'beta:'+A,B);draft['events']['beta:'+A]['attempts'][-1]['legacy']=True
        observed=run(draft,'beta:'+A)
        class Provider:
            def recent_builds(self,_):return [observed]
            def request(self,route,data=None):
                if data is not None:raise AssertionError('duplicate POST')
                return {'ref':'refs/heads/main','object':{'sha':B}}
        self.assertEqual(dispatch_pending(self.store,Provider(),B),[])
        self.assertEqual(self.store.read()['events']['beta:'+A]['attempts'][0]['state'],'qualified')

    def test_wrong_main_ref_prevents_intent_and_post(self):
        class Provider:
            def request(self,route,data=None):return {'ref':'refs/heads/main','object':{'sha':C}}
        with self.assertRaisesRegex(j.JournalError,'REMOTE_MAIN_DRIFT'):dispatch_pending(self.store,Provider(),B)
        self.assertEqual(self.store.read(),self.state)

class DiscoveryWindowTests(unittest.TestCase):
    def test_explicit_window_uses_date_filter_and_paginates_old_release_page(self):
        class Api:
            def __init__(self):self.routes=[]
            def get(self,route):
                self.routes.append(route)
                if route.startswith('/actions/'):return {'workflow_runs':[]}
                if route.startswith('/releases?') and route.endswith('page=1'):
                    return [{'published_at':j.timestamp(OLD-timedelta(days=30)), 'id':i+1} for i in range(100)]
                if route.startswith('/releases?'):return [{'id':201,'tag_name':'v1.0','published_at':j.timestamp(OLD),'draft':False,'prerelease':False}]
                if route.startswith('/git/ref/'):return {'object':{'sha':A,'type':'commit'}}
                raise AssertionError(route)
        api=Api();r=build_window_report(api,OLD-timedelta(hours=1),OLD+timedelta(days=7));self.assertEqual(len(r['candidates']),1)
        self.assertIn('created=',api.routes[0]);self.assertTrue(any(x.endswith('page=2') for x in api.routes))

if __name__=='__main__':unittest.main()
