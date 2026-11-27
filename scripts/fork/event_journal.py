#!/usr/bin/env python3
"""Durable, source-bound candidate state. No signing, publication or device operations.

A journal is a reviewed input, not proof that a provider mutation happened.
An intent with an unknown outcome is never retried automatically.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone, timedelta
from typing import Any

SHA = re.compile(r'^[0-9a-f]{40}$')
TAG = re.compile(r'^v[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
REPO = 'Mikeyphw/BakaSU'
UPSTREAM = 'Baka-SU/BakaSU'
MAX_VERSION = 2_099_999_999
MAX_EVENTS = 4096
MAX_ATTEMPTS = 3
MAX_WINDOW = timedelta(days=7)
OVERLAP = timedelta(hours=1)


class JournalError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise JournalError(reason)


def sha(value: Any) -> bool:
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def integer(value: Any, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def utc(value: str) -> datetime:
    require(isinstance(value, str), 'JOURNAL_TIME_INVALID')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise JournalError('JOURNAL_TIME_INVALID') from None
    require(parsed.tzinfo is not None, 'JOURNAL_TIME_NAIVE')
    return parsed.astimezone(timezone.utc)


def timestamp(value: datetime) -> str:
    require(value.tzinfo is not None, 'JOURNAL_TIME_NAIVE')
    return value.astimezone(timezone.utc).isoformat()


def strict_json(raw: bytes) -> Any:
    require(len(raw) <= 8_000_000, 'JOURNAL_TOO_LARGE')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'JOURNAL_DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(JournalError('JOURNAL_NONFINITE_JSON')))
    except (ValueError, UnicodeError) as exc:
        raise JournalError('JOURNAL_JSON_INVALID') from exc


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def event(candidate: dict) -> dict:
    require(isinstance(candidate, dict), 'EVENT_INVALID')
    channel = candidate.get('channel')
    source = candidate.get('upstreamSha')
    require(channel in ('beta', 'stable') and sha(source), 'EVENT_SOURCE_INVALID')
    ident = candidate.get('upstreamRunId' if channel == 'beta' else 'upstreamReleaseId')
    require(integer(ident, 1, 2**63-1), 'EVENT_ID_INVALID')
    tag = candidate.get('upstreamTag') if channel == 'stable' else None
    require(channel == 'beta' or isinstance(tag, str) and TAG.fullmatch(tag) is not None, 'EVENT_TAG_INVALID')
    key = f'beta:{source}' if channel == 'beta' else f'stable:{tag}:{source}'
    require(candidate.get('key') == key, 'EVENT_KEY_MISMATCH')
    return {'key': key, 'channel': channel, 'source': source, 'eventId': ident,
            'tag': tag, 'eventAt': timestamp(utc(candidate.get('eventAt')))}


def initial(checkpoint: str, version_floor: int) -> dict:
    require(integer(version_floor, 0, MAX_VERSION), 'VERSION_FLOOR_INVALID')
    return {'schemaVersion': 1, 'repository': REPO, 'upstream': UPSTREAM,
            'checkpoint': timestamp(utc(checkpoint)), 'versionFloor': version_floor,
            'nextVersion': version_floor + 1, 'revision': 0, 'events': {}}


def validate(state: dict) -> None:
    require(isinstance(state, dict) and set(state) == {'schemaVersion','repository','upstream','checkpoint','versionFloor','nextVersion','revision','events'}, 'JOURNAL_SCHEMA_INVALID')
    require(state['schemaVersion'] == 1 and state['repository'] == REPO and state['upstream'] == UPSTREAM, 'JOURNAL_REPOSITORY_INVALID')
    utc(state['checkpoint'])
    require(integer(state['revision'],0,2**63-1) and integer(state['versionFloor'],0,MAX_VERSION) and integer(state['nextVersion'],1,MAX_VERSION+1), 'JOURNAL_COUNTER_INVALID')
    events = state['events']
    require(isinstance(events,dict) and len(events)<=MAX_EVENTS,'JOURNAL_EVENT_LIMIT')
    versions = set(); run_ids=set()
    for key,row in events.items():
        require(isinstance(row,dict) and set(row)=={'event','attempts','reservation','promotion'},'JOURNAL_ROW_INVALID')
        e=row['event']; require(isinstance(e,dict),'EVENT_INVALID')
        reconstructed=event({'key':key,'channel':e.get('channel'),'upstreamSha':e.get('source'),
            'upstreamRunId':e.get('eventId'),'upstreamReleaseId':e.get('eventId'),'upstreamTag':e.get('tag'),'eventAt':e.get('eventAt')})
        require(e==reconstructed,'JOURNAL_EVENT_MISMATCH')
        attempts=row['attempts']; require(isinstance(attempts,list) and len(attempts)<=MAX_ATTEMPTS,'JOURNAL_ATTEMPT_LIMIT')
        for n,a in enumerate(attempts,1):
            require(isinstance(a,dict) and set(a)=={'number','forkSha','intentId','runId','state','conclusion','legacy'},'JOURNAL_ATTEMPT_INVALID')
            require(type(a['legacy']) is bool and a['number']==n and sha(a['forkSha']) and a['intentId']==intent_id(key,a['forkSha'],n),'JOURNAL_INTENT_IDENTITY')
            require(a['state'] in ('intent','observed','failed','qualified','not-sent'),'JOURNAL_ATTEMPT_STATE')
            if a['state'] in ('intent','not-sent'):
                require(a['runId'] is None and a['conclusion']==(None if a['state']=='intent' else 'main-drift-before-dispatch'),'JOURNAL_INTENT_OUTCOME')
            else:
                require(integer(a['runId'],1,2**63-1) and a['runId'] not in run_ids,'JOURNAL_RUN_ID_INVALID');run_ids.add(a['runId'])
                require((a['state']=='qualified' and a['conclusion']=='success') or (a['state']=='failed' and a['conclusion'] in ('failure','cancelled','timed_out','action_required','startup_failure','stale','skipped')) or (a['state']=='observed' and a['conclusion'] is None),'JOURNAL_RUN_CONCLUSION')
            if n<len(attempts):require(a['state'] in ('failed','not-sent'),'JOURNAL_RETRY_WITHOUT_FAILURE')
        p=row['promotion']; res=row['reservation']
        if p is not None:
            require(isinstance(p,dict) and set(p)=={'commit','tree','diagnosticRunId','diagnosticTree','diagnosticArtifactId','diagnosticArtifactSha256'},'PROMOTION_SCHEMA_INVALID')
            require(sha(p['commit']) and sha(p['tree']) and p['tree']==p['diagnosticTree'] and attempts and attempts[-1]['state']=='qualified' and p['diagnosticRunId']==attempts[-1]['runId'] and integer(p['diagnosticArtifactId'],1,2**63-1) and isinstance(p['diagnosticArtifactSha256'],str) and re.fullmatch(r'[0-9a-f]{64}',p['diagnosticArtifactSha256']) is not None,'PROMOTION_IDENTITY_INVALID')
        if res is not None:
            require(p is not None and isinstance(res,dict) and set(res)=={'versionCode','sourceCommit','sourceTree'},'RESERVATION_INVALID')
            code=res['versionCode'];require(integer(code,1,MAX_VERSION) and code<state['nextVersion'] and code not in versions,'VERSION_DUPLICATE_OR_RANGE')
            require(res['sourceCommit']==p['commit'] and res['sourceTree']==p['tree'],'VERSION_SOURCE_MISMATCH')
            versions.add(code)
    require(state['nextVersion']>max([state['versionFloor'],*versions]),'VERSION_COUNTER_REGRESSION')


def intent_id(key: str, fork_sha: str, number: int) -> str:
    return digest([REPO,key,fork_sha,number])[:32]


def discovery_window(state: dict, now: datetime) -> tuple[datetime,datetime]:
    validate(state); require(now.tzinfo is not None,'JOURNAL_TIME_NAIVE')
    last=utc(state['checkpoint']); now=now.astimezone(timezone.utc)
    require(now>=last,'JOURNAL_CLOCK_REGRESSION')
    return last-OVERLAP,min(now,last+MAX_WINDOW)


def ingest(state: dict, report: dict, now: datetime) -> dict:
    """Advance a bounded cursor only after a complete exact-window scan."""
    validate(state); start,end=discovery_window(state,now)
    require(isinstance(report,dict) and report.get('schemaVersion')==1 and report.get('mode')=='discovery-only' and report.get('forkRepository')==REPO and report.get('upstreamRepository')==UPSTREAM,'REPORT_REPOSITORY_INVALID')
    require(utc(report.get('lookbackStart'))==start and utc(report.get('checkedAt'))==end,'REPORT_WINDOW_MISMATCH')
    candidates=report.get('candidates'); require(isinstance(candidates,list) and len(candidates)<=120,'REPORT_CANDIDATES_INVALID')
    result=copy.deepcopy(state); seen=set()
    for item in candidates:
        e=event(item); key=e['key']; require(key not in seen,'REPORT_DUPLICATE_EVENT');seen.add(key)
        require(start<=utc(e['eventAt'])<=end,'EVENT_OUTSIDE_WINDOW')
        if key in result['events']:
            previous=result['events'][key]['event']
            # Reruns for the same beta source are aliases, not fresh attempts.
            require(previous['channel']==e['channel'] and previous['source']==e['source'] and previous['tag']==e['tag'],'EVENT_IDENTITY_DRIFT')
            if e['channel']=='stable':require(previous['eventId']==e['eventId'],'STABLE_EVENT_ID_DRIFT')
        else:
            if e['channel']=='stable':
                require(not any(row['event']['tag']==e['tag'] for row in result['events'].values()),'STABLE_TAG_MOVED')
            result['events'][key]={'event':e,'attempts':[],'reservation':None,'promotion':None}
    unsettled=report.get('unsettledBeta');require(isinstance(unsettled,list) and len(unsettled)<=400,'REPORT_UNSETTLED_INVALID')
    unresolved=[];run_ids=set()
    for item in unsettled:
        require(isinstance(item,dict) and set(item)=={'upstreamRunId','eventAt'} and integer(item['upstreamRunId'],1,2**63-1) and item['upstreamRunId'] not in run_ids,'REPORT_UNSETTLED_INVALID')
        run_ids.add(item['upstreamRunId']);when=utc(item['eventAt']);require(start<=when<=end,'REPORT_UNSETTLED_OUTSIDE_WINDOW');unresolved.append(when)
    # Do not skip a build whose creation preceded a long-running completion.
    safe_end=max(utc(state['checkpoint']),min([end,*unresolved]))
    result['checkpoint']=timestamp(safe_end);result['revision']+=1;validate(result);return result


def pending(state: dict, fork_sha: str) -> list[str]:
    validate(state);require(sha(fork_sha),'FORK_SHA_INVALID')
    # A failed attempt at the same source needs deliberate review; a new main
    # can retry a known failed attempt, bounded by the global per-event cap.
    return [key for key,row in sorted(state['events'].items(),key=lambda kv:(kv[1]['event']['channel']!='stable',kv[1]['event']['eventAt'],kv[0]))
            if not row['attempts'] or (len(row['attempts'])<MAX_ATTEMPTS and row['attempts'][-1]['state'] in ('failed','not-sent') and row['attempts'][-1]['forkSha']!=fork_sha)]


def begin(state: dict,key: str,fork_sha: str) -> tuple[dict,dict]:
    require(key in pending(state,fork_sha),'EVENT_NOT_DISPATCHABLE')
    result=copy.deepcopy(state); attempts=result['events'][key]['attempts']; n=len(attempts)+1
    a={'number':n,'forkSha':fork_sha,'intentId':intent_id(key,fork_sha,n),'runId':None,'state':'intent','conclusion':None,'legacy':False}
    attempts.append(a);result['revision']+=1;validate(result);return result,copy.deepcopy(a)


def title(e: dict,a: dict) -> str:
    base=f"F05/{e['channel']}/{e['source']}/{a['forkSha']}"
    return base if a['legacy'] else base+"/"+a['intentId']


def observe(state: dict,key: str,runs: list[dict]) -> dict:
    validate(state);require(key in state['events'],'EVENT_UNKNOWN')
    row=state['events'][key];require(bool(row['attempts']),'INTENT_MISSING');a=row['attempts'][-1]
    matches=[run for run in runs if run.get('display_title')==title(row['event'],a)]
    require(len(matches)<=1,'AMBIGUOUS_DISPATCH_OUTCOME')
    if not matches:return copy.deepcopy(state) # never infer absent remote mutation
    run=matches[0];require(run.get('event')=='workflow_dispatch' and run.get('head_branch')=='main' and run.get('head_sha')==a['forkSha'] and (run.get('head_repository') or {}).get('full_name')==REPO and str(run.get('path','')).split('@',1)[0].removeprefix('/')=='.github/workflows/fork-source-build.yml' and integer(run.get('id'),1,2**63-1),'RUN_IDENTITY_MISMATCH')
    require(a['runId'] in (None,run['id']),'RUN_ID_CHANGED')
    conclusion=run.get('conclusion');status=run.get('status')
    if status=='completed':
        next_state='qualified' if conclusion=='success' else 'failed'
    else:
        require(status in ('queued','in_progress','waiting','requested','pending') and conclusion is None,'RUN_STATUS_INVALID');next_state='observed'
    if a['state'] in ('qualified','failed','not-sent'):
        require((a['state'],a['conclusion'])==(next_state,conclusion),'TERMINAL_RUN_DRIFT');return copy.deepcopy(state)
    result=copy.deepcopy(state);target=result['events'][key]['attempts'][-1];target.update(runId=run['id'],state=next_state,conclusion=conclusion);result['revision']+=1;validate(result);return result


def not_sent(state: dict,key: str)->dict:
    validate(state);result=copy.deepcopy(state);a=result['events'][key]['attempts'][-1]
    require(a['state']=='intent','NOT_SENT_REQUIRES_INTENT');a.update(state='not-sent',conclusion='main-drift-before-dispatch');result['revision']+=1;validate(result);return result


def adopt_legacy(state: dict,key: str,fork_sha: str,runs: list[dict]) -> dict:
    # Adoption is atomic: the legacy intent is not persisted independently of
    # an exact authenticated run observation. No duplicate POST is performed.
    draft,attempt=begin(state,key,fork_sha)
    draft['events'][key]['attempts'][-1]['legacy']=True
    observed=observe(draft,key,runs)
    if observed==draft:return copy.deepcopy(state)
    observed['revision']=state['revision']+1;validate(observed);return observed


def reserve(state: dict,key: str,promotion: dict,verified_floor: int) -> tuple[dict,int]:
    """Allocate one global code across stable and beta; never reuse or wrap.

    The caller MUST verify promotion ancestry, exact tree and diagnostic
    artifact provenance before supplying promotion. This function validates
    the binding and counter only, not a remote proof.
    """
    validate(state);require(key in state['events'],'EVENT_UNKNOWN');require(integer(verified_floor,0,MAX_VERSION),'VERSION_FLOOR_INVALID')
    result=copy.deepcopy(state);row=result['events'][key]
    require(row['promotion'] in (None,promotion),'PROMOTION_CHANGED')
    row['promotion']=copy.deepcopy(promotion)
    old=row['reservation']
    if old is not None:
        require(old['versionCode']>verified_floor,'RESERVED_CODE_ALREADY_PUBLISHED_OR_STALE');return result,old['versionCode']
    result['versionFloor']=max(result['versionFloor'],verified_floor)
    code=max(result['nextVersion'],result['versionFloor']+1);require(code<=MAX_VERSION,'VERSION_SPACE_EXHAUSTED')
    row['reservation']={'versionCode':code,'sourceCommit':promotion['commit'],'sourceTree':promotion['tree']}
    result['nextVersion']=code+1;result['revision']+=1;validate(result);return result,code
