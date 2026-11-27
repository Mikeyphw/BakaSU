"""Exact reviewed signing reservation, provider artifact and committed source identities.

No credential access or provider mutation. A journal export is evidence for a
separate reviewed native registry update; it never grants signing authority.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess

import event_journal as journal

REPO = journal.REPO
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_REGISTRY = 1024 * 1024
F05_PATH = '.github/workflows/fork-source-build.yml'
F06_PATH = '.github/workflows/fork-f06-signed-manager.yml'
SIGNING_PATH = 'config/fork-signing-contract.json'
RESERVATION_FIELDS = {
    'reservationId', 'eventKey', 'channel', 'upstreamSha', 'upstreamEventId',
    'upstreamTag', 'diagnosticRunId', 'diagnosticForkSha', 'diagnosticIntentId',
    'diagnosticLegacy', 'diagnosticArtifactId', 'diagnosticArtifactSha256',
    'sourceCommit', 'sourceTree', 'versionCode',
}


class Refused(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


def digest(value):
    return journal.digest(value)


def sha256(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def positive(value):
    return journal.integer(value, 1, 2**63 - 1)


def read_json(path: Path, limit=MAX_REGISTRY):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit,
            'LINEAGE_JSON_FILE_INVALID')
    obj = journal.strict_json(path.read_bytes())
    require(isinstance(obj, dict), 'LINEAGE_JSON_OBJECT_REQUIRED')
    return obj


def export_reservation(state, key):
    journal.validate(state)
    require(key in state['events'], 'SIGNING_EVENT_UNKNOWN')
    row = state['events'][key]
    require(row['reservation'] is not None and row['promotion'] is not None,
            'SIGNING_RESERVATION_MISSING')
    e, p, a = row['event'], row['promotion'], row['attempts'][-1]
    result = dict(eventKey=key, channel=e['channel'], upstreamSha=e['source'],
                  upstreamEventId=e['eventId'], upstreamTag=e['tag'], diagnosticRunId=p['diagnosticRunId'],
                  diagnosticForkSha=a['forkSha'], diagnosticIntentId=a['intentId'],
                  diagnosticLegacy=a['legacy'], diagnosticArtifactId=p['diagnosticArtifactId'],
                  diagnosticArtifactSha256=p['diagnosticArtifactSha256'], sourceCommit=p['commit'],
                  sourceTree=p['tree'], versionCode=row['reservation']['versionCode'])
    result['reservationId'] = digest(result)
    validate_reservation(result)
    return result


def validate_reservation(row):
    require(isinstance(row, dict) and set(row) == RESERVATION_FIELDS, 'SIGNING_RESERVATION_SCHEMA')
    channel, upstream, tag = row['channel'], row['upstreamSha'], row['upstreamTag']
    require(channel in ('beta', 'stable') and journal.sha(upstream), 'SIGNING_UPSTREAM_IDENTITY')
    require((channel == 'beta' and tag is None and row['eventKey'] == 'beta:' + upstream) or
            (channel == 'stable' and isinstance(tag, str) and journal.TAG.fullmatch(tag) and
             row['eventKey'] == 'stable:' + tag + ':' + upstream), 'SIGNING_EVENT_KEY')
    require(all(journal.sha(row[k]) for k in ('sourceCommit','sourceTree','diagnosticForkSha')) and
            all(positive(row[k]) for k in ('upstreamEventId','diagnosticRunId','diagnosticArtifactId')) and
            isinstance(row['diagnosticIntentId'], str) and re.fullmatch(r'[0-9a-f]{32}', row['diagnosticIntentId']) and
            type(row['diagnosticLegacy']) is bool and sha256(row['diagnosticArtifactSha256']) and
            journal.integer(row['versionCode'], 1, journal.MAX_VERSION), 'SIGNING_RESERVATION_IDENTITY')
    require(row['reservationId'] == digest({k:v for k,v in row.items() if k != 'reservationId'}),
            'SIGNING_RESERVATION_DIGEST_MISMATCH')
    return row


def signing_policy(raw):
    require(isinstance(raw, dict) and raw.get('schemaVersion') == 2 and
            raw.get('repository') == REPO and raw.get('branch') == 'main' and
            raw.get('managerPackage') == 'com.mikeyphw.bakasu' and
            raw.get('buildMode') == 'manual-promoted-reserved-signing-diagnostic' and
            raw.get('releasePublication') is False and raw.get('deviceInstallation') is False and
            raw.get('requireV2Signature') is True and raw.get('requireExpectedSignerFingerprint') is True and
            raw.get('compatibilityManifestPublished') is False and
            'certificateSha256' in raw and (raw['certificateSha256'] is None or sha256(raw['certificateSha256'])) and
            isinstance(raw.get('approvedReservations'), list) and len(raw['approvedReservations']) <= journal.MAX_EVENTS,
            'SIGNING_POLICY_INVALID')
    seen = {key:set() for key in ('reservationId','versionCode','eventKey','diagnosticRunId')}
    for row in raw['approvedReservations']:
        validate_reservation(row)
        for key, values in seen.items():
            require(row[key] not in values, 'SIGNING_RESERVATION_DUPLICATE_'+key)
            values.add(row[key])
    require(not raw['approvedReservations'] or sha256(raw['certificateSha256']), 'SIGNING_CERTIFICATE_NOT_REVIEWED')
    return raw


def reviewed_reservation(policy, ident, version):
    signing_policy(policy)
    require(sha256(ident) and journal.integer(version, 1, journal.MAX_VERSION), 'SIGNING_SELECTION_INVALID')
    rows = [x for x in policy['approvedReservations'] if x['reservationId'] == ident and x['versionCode'] == version]
    require(len(rows) == 1 and sha256(policy['certificateSha256']), 'SIGNING_REVIEWED_RESERVATION_REQUIRED')
    return rows[0]


def git(root, *args):
    proc = subprocess.run(['git','--no-replace-objects','-C',str(root),*args], capture_output=True, timeout=45)
    require(proc.returncode == 0, 'LINEAGE_GIT_'+args[0])
    return proc.stdout


def ancestor(root, source, head):
    require(journal.sha(source) and journal.sha(head), 'LINEAGE_ANCESTRY_SHA_INVALID')
    proc = subprocess.run(['git','--no-replace-objects','-C',str(root),'merge-base','--is-ancestor',source,head],
                          capture_output=True, timeout=45)
    require(proc.returncode in (0,1), 'LINEAGE_ANCESTRY_UNAVAILABLE')
    return proc.returncode == 0


def committed_source(root, row, head):
    validate_reservation(row)
    require(journal.sha(head) and ancestor(root,row['sourceCommit'],head) and
            ancestor(root,row['diagnosticForkSha'],row['sourceCommit']), 'LINEAGE_SOURCE_NOT_PROMOTED')
    for expr, value in ((row['sourceCommit']+'^{commit}',row['sourceCommit']),
                        (row['sourceCommit']+'^{tree}',row['sourceTree'])):
        require(git(root,'rev-parse','--verify',expr).decode().strip() == value, 'LINEAGE_SOURCE_TREE_DRIFT')


def policy_at(root, head):
    require(journal.sha(head), 'SIGNING_POLICY_HEAD_INVALID')
    return signing_policy(journal.strict_json(git(root,'show',head+':'+SIGNING_PATH)))


def history(root,head,path):
    require(journal.sha(head), 'LINEAGE_HISTORY_HEAD_INVALID')
    revisions = git(root,'log','--full-history','--format=%H','--max-count=4097',head,'--',path).decode().splitlines()
    require(0 < len(revisions) <= 4096, 'LINEAGE_HISTORY_UNAVAILABLE_OR_TOO_LARGE')
    for revision in revisions:
        raw = journal.strict_json(git(root,'show',revision+':'+path))
        require(isinstance(raw,dict) and raw.get('schemaVersion') in (1,2), 'LINEAGE_HISTORY_SCHEMA_INVALID')
        yield raw


def signer_continuity(root, head, certificate):
    require(sha256(certificate), 'SIGNING_CERTIFICATE_NOT_REVIEWED')
    current=policy_at(root,head)
    require(current['certificateSha256']==certificate,'SIGNING_CURRENT_CERTIFICATE_DRIFT')
    present={row['reservationId']:row for row in current['approvedReservations']}
    for raw in history(root,head,SIGNING_PATH):
        if raw['schemaVersion'] == 2:
            previous = signing_policy(raw)
            require(previous['certificateSha256'] is None or previous['certificateSha256'] == certificate,
                    'SIGNING_CERTIFICATE_ROTATION_REFUSED')
            require(all(present.get(row['reservationId'])==row for row in previous['approvedReservations']),
                    'SIGNING_HISTORICAL_RESERVATION_REMOVED_OR_CHANGED')


def run_identity(run, ident, head, path, attempt=None):
    require(isinstance(run,dict) and run.get('id') == ident and run.get('event') == 'workflow_dispatch' and
            run.get('head_branch') == 'main' and run.get('head_sha') == head and
            (run.get('head_repository') or {}).get('full_name') == REPO and
            run.get('status') == 'completed' and run.get('conclusion') == 'success' and
            positive(run.get('run_attempt')) and (attempt is None or run['run_attempt'] == attempt) and
            str(run.get('path','')).split('@',1)[0].removeprefix('/') in (path,REPO+'/'+path),
            'LINEAGE_WORKFLOW_RUN_MISMATCH')


def artifact_identity(meta, artifact_id, artifact_sha, run_id, head, name):
    run = meta.get('workflow_run') or {} if isinstance(meta,dict) else {}
    require(isinstance(meta,dict) and meta.get('id') == artifact_id and meta.get('name') == name and
            meta.get('digest') == 'sha256:'+artifact_sha and meta.get('expired') is False and
            isinstance(run,dict) and run.get('id') == run_id and run.get('head_sha') == head and positive(meta.get('size_in_bytes')),
            'LINEAGE_WORKFLOW_ARTIFACT_MISMATCH')


def verify_diagnostic(row, request):
    validate_reservation(row)
    run = request('/actions/runs/'+str(row['diagnosticRunId']))
    run_identity(run,row['diagnosticRunId'],row['diagnosticForkSha'],F05_PATH)
    title = f"F05/{row['channel']}/{row['upstreamSha']}/{row['diagnosticForkSha']}"
    if not row['diagnosticLegacy']:
        title += '/'+row['diagnosticIntentId']
    require(run.get('display_title') == title, 'LINEAGE_DIAGNOSTIC_EVENT_DRIFT')
    meta = request('/actions/artifacts/'+str(row['diagnosticArtifactId']))
    artifact_identity(meta,row['diagnosticArtifactId'],row['diagnosticArtifactSha256'],
                      row['diagnosticRunId'],row['diagnosticForkSha'],f"f05-promotion-{row['diagnosticRunId']}")
