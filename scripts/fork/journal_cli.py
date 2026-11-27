#!/usr/bin/env python3
"""Owner-side persistent event discovery, reconciliation and source-pinned dispatch.

A durable intent is committed locally before any existing F05 dispatch API
call. No automatic replay of an ambiguous dispatch; no source branch writes.
The caller must use a private persistent directory, not a hosted runner cache.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import tempfile
import subprocess
import zipfile

import event_journal as journal
from journal_store import LocalJournal
from upstream_events import GitHubJsonClient, build_window_report, UpstreamDiscoveryError
from f05_dispatch import Client, DispatchError, MAX_DISPATCH


def reconcile(store,client):
    state=store.read()
    for key,row in state['events'].items():
        if not row['attempts'] or row['attempts'][-1]['state'] in ('qualified','failed','not-sent'):continue
        attempt=row['attempts'][-1]
        # Direct run lookup for a previously identified attempt; otherwise a
        # bounded complete run scan. No absence inference on API ambiguity.
        if attempt['runId'] is not None:
            runs=[client.request(f"/actions/runs/{attempt['runId']}")]
        else:
            earliest=journal.utc(row['event']['eventAt']).strftime('%Y-%m-%dT%H:%M:%SZ')
            runs=client.recent_builds(earliest)
        successor=journal.observe(state,key,runs)
        if successor!=state:store.replace(state,successor);state=successor
    return state


def dispatch_pending(store,client,fork_sha,limit=MAX_DISPATCH):
    journal.require(journal.sha(fork_sha) and type(limit) is int and 1<=limit<=MAX_DISPATCH,'DISPATCH_SCOPE_INVALID')
    # Verify the actual canonical remote main, not merely caller input.
    ref=client.request('/git/ref/heads/main')
    journal.require(ref.get('ref')=='refs/heads/main' and ref.get('object',{}).get('sha')==fork_sha,'REMOTE_MAIN_DRIFT')
    state=reconcile(store,client)
    accepted=[]
    for key in journal.pending(state,fork_sha)[:limit]:
        e=state['events'][key]['event']
        earliest=journal.utc(e['eventAt']).strftime('%Y-%m-%dT%H:%M:%SZ')
        runs=client.recent_builds(earliest)
        adopted=journal.adopt_legacy(state,key,fork_sha,runs)
        if adopted!=state:
            store.replace(state,adopted);state=adopted;continue
        successor,intent=journal.begin(state,key,fork_sha)
        existing=journal.observe(successor,key,runs)
        if existing!=successor:
            existing['revision']=state['revision']+1
            store.replace(state,existing);state=existing;continue
        store.replace(state,successor);state=successor
        e=state['events'][key]['event']
        # Recheck the fork source after durable intent and before the POST.
        ref=client.request('/git/ref/heads/main')
        if ref.get('ref')!='refs/heads/main' or ref.get('object',{}).get('sha')!=fork_sha:
            refused=journal.not_sent(state,key);store.replace(state,refused)
            raise journal.JournalError('REMOTE_MAIN_DRIFT_AFTER_INTENT_NOT_SENT')
        client.request('/actions/workflows/fork-source-build.yml/dispatches',{'ref':'main','inputs':{'channel':e['channel'],'upstream_sha':e['source'],'upstream_event_id':str(e['eventId']),'fork_sha':fork_sha,'journal_attempt':intent['intentId']}})
        accepted.append(intent['intentId'])
    return accepted


def review(store,client,key,repo,artifact,artifact_id,promoted_commit=None):
    import promotion_plan as promotion
    state=store.read();journal.require(key in state['events'],'EVENT_UNKNOWN')
    row=state['events'][key];journal.require(bool(row['attempts']),'PROMOTION_ATTEMPT_MISSING')
    for args in (('remote','get-url','--all','origin'),('remote','get-url','--push','--all','origin')):
        origin=promotion.git(repo,*args).decode().strip()
        journal.require(origin in ('https://github.com/'+journal.REPO,'https://github.com/'+journal.REPO+'.git','git@github.com:'+journal.REPO,'git@github.com:'+journal.REPO+'.git'),'PROMOTION_ORIGIN_MISMATCH')
    ref=client.request('/git/ref/heads/main');main=ref.get('object',{}).get('sha')
    journal.require(ref.get('ref')=='refs/heads/main' and journal.sha(main) and promotion.oid(repo,main+'^{commit}')==main,'PROMOTION_MAIN_OBJECT_UNAVAILABLE')
    report,bundle,artifact_sha=promotion.verify_artifact(client,row,artifact,artifact_id)
    # Local object import is isolated; no source branch/ref in the user
    # checkout is changed. Use a private temporary bare repository.
    with tempfile.TemporaryDirectory(prefix='bakasu-promotion-') as folder:
        scratch=Path(folder)/'review.git'
        subprocess.run(['git','clone','--bare','--no-hardlinks',str(repo),str(scratch)],check=True,capture_output=True,timeout=120)
        if bundle is not None:
            path=Path(folder)/'integration.bundle';path.write_bytes(bundle)
            promotion.git(scratch,'bundle','verify',str(path))
            promotion.git(scratch,'fetch','--no-tags',str(path),'HEAD:refs/heads/diagnostic')
            journal.require(promotion.oid(scratch,'refs/heads/diagnostic')==report.get('mergedSha'),'PROMOTION_IMPORTED_HEAD_MISMATCH')
        if promoted_commit is None:
            result=promotion.inventory(scratch,row,report,main)
            result.update(artifactId=artifact_id,artifactSha256=artifact_sha)
            return result
        proof=promotion.promoted(scratch,row,report,promoted_commit,main)
        proof.update(diagnosticArtifactId=artifact_id,diagnosticArtifactSha256=artifact_sha)
    floor=promotion.published_version_floor(client)
    remote=client.request('/git/ref/heads/main')
    journal.require(remote.get('ref')=='refs/heads/main' and remote.get('object',{}).get('sha')==main,'PROMOTION_MAIN_DRIFT_BEFORE_RESERVATION')
    successor,code=journal.reserve(state,key,proof,floor)
    if successor!=state:store.replace(state,successor)
    return {'eventKey':key,'versionCode':code,'promotion':proof,'journalRevision':successor['revision'],'status':'RESERVED_NOT_SIGNED_NOT_PUBLISHED'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--journal',required=True,type=Path)
    sub=p.add_subparsers(dest='command',required=True)
    init=sub.add_parser('initialize');init.add_argument('--checkpoint',required=True);init.add_argument('--version-floor',required=True,type=int);init.add_argument('--yes',action='store_true')
    sub.add_parser('discover');sub.add_parser('reconcile');sub.add_parser('status')
    export=sub.add_parser('export-signing-reservation');export.add_argument('--event-key',required=True)
    tick=sub.add_parser('tick');tick.add_argument('--fork-sha',required=True);tick.add_argument('--yes',action='store_true')
    d=sub.add_parser('dispatch');d.add_argument('--fork-sha',required=True);d.add_argument('--yes',action='store_true')
    for command in ('plan-promotion','reserve-version'):
        c=sub.add_parser(command);c.add_argument('--repo',required=True,type=Path);c.add_argument('--event-key',required=True);c.add_argument('--artifact',required=True,type=Path);c.add_argument('--artifact-id',required=True,type=int)
        if command=='reserve-version':c.add_argument('--promoted-commit',required=True);c.add_argument('--yes',action='store_true')
    a=p.parse_args(argv)
    try:
        store=LocalJournal(a.journal)
        if a.command=='export-signing-reservation':
            from release_lineage import export_reservation
            sys.stdout.buffer.write(journal.canonical(export_reservation(store.read(),a.event_key)));return 0
        if a.command in ('plan-promotion','reserve-version'):
            if a.command=='reserve-version':journal.require(a.yes,'EXPLICIT_RESERVATION_APPROVAL_REQUIRED')
            value=review(store,Client(os.environ.get('GITHUB_TOKEN','')),a.event_key,a.repo.resolve(),a.artifact,a.artifact_id,getattr(a,'promoted_commit',None))
            sys.stdout.buffer.write(journal.canonical(value));return 0
        if a.command=='initialize':
            journal.require(a.yes,'EXPLICIT_INITIALIZATION_APPROVAL_REQUIRED');store.initialize(journal.initial(a.checkpoint,a.version_floor))
        elif a.command in ('discover','tick'):
            if a.command=='tick':journal.require(a.yes,'EXPLICIT_DISPATCH_APPROVAL_REQUIRED')
            now=datetime.now(timezone.utc);state=store.read();start,end=journal.discovery_window(state,now)
            report=build_window_report(GitHubJsonClient(os.environ.get('GITHUB_TOKEN','')),start,end)
            successor=journal.ingest(state,report,now);store.replace(state,successor)
            if a.command=='tick':dispatch_pending(store,Client(os.environ.get('GITHUB_TOKEN','')),a.fork_sha)
        elif a.command=='reconcile':reconcile(store,Client(os.environ.get('GITHUB_TOKEN','')))
        elif a.command=='dispatch':
            journal.require(a.yes,'EXPLICIT_DISPATCH_APPROVAL_REQUIRED');dispatch_pending(store,Client(os.environ.get('GITHUB_TOKEN','')),a.fork_sha)
        sys.stdout.buffer.write(journal.canonical(store.read()));return 0
    except (ValueError,DispatchError,UpstreamDiscoveryError,OSError,KeyError,TypeError,subprocess.SubprocessError,zipfile.BadZipFile) as exc:
        print('BK_GAP03_JOURNAL_REFUSED '+str(exc),file=sys.stderr);return 2

if __name__=='__main__':sys.exit(main())
