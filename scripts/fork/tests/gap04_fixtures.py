"""Synthetic lineage records only; no production signing key or remote mutation."""
import hashlib
import json
from pathlib import Path

import release_lineage as lineage

ROOT = Path(__file__).resolve().parents[3]


def reservation(commit='a'*40, tree='d'*40, diagnostic='b'*40, version=40005):
    row = dict(eventKey='beta:'+'e'*40, channel='beta', upstreamSha='e'*40,
               upstreamEventId=100, upstreamTag=None, diagnosticRunId=1001,
               diagnosticForkSha=diagnostic, diagnosticIntentId='1'*32,
               diagnosticLegacy=False, diagnosticArtifactId=1002,
               diagnosticArtifactSha256='2'*64, sourceCommit=commit,
               sourceTree=tree, versionCode=version)
    row['reservationId']=lineage.digest(row)
    return row


def policy(row, cert):
    value=json.loads((ROOT/'config/fork-signing-contract.json').read_text())
    value.update(certificateSha256=cert,approvedReservations=[row])
    return value


def stage(row, fork, cert, run=310, attempt=1):
    return dict(schemaVersion=2,mode='F06-promoted-reservation',status='source-promoted-reviewed',
                forkSha=fork,reservation=row,certificateSha256=cert,runId=run,runAttempt=attempt)


def signed(row, fork, cert, run=310, attempt=1):
    return dict(schemaVersion=2,repository=lineage.REPO,mode='F06-signed-artifact-not-a-release',
                status='signed-verified',releaseQualified=False,deviceQualified=False,
                compatibilityQualified=False,certificateSha256=cert,reservationId=row['reservationId'],
                source=stage(row,fork,cert,run,attempt),apks=[])


def review(row, fork, cert, run=310, attempt=1, tag='f07-v1.2.3-beta.1'):
    return dict(f06RunId=run,f06RunAttempt=attempt,tag=tag,channel=row['channel'],
                sourceMergedSha=row['sourceCommit'],sourceForkSha=fork,sourceTree=row['sourceTree'],
                certificateSha256=cert,managerUapi=3,minimumKernelSuVersion=40000,
                versionCode=row['versionCode'],reservationId=row['reservationId'],
                signedProvenanceSha256='3'*64,evidenceArtifactId=2001,evidenceArtifactSha256='4'*64,
                apkArtifactId=2002,apkArtifactSha256='5'*64)


def run_info(entry):
    return dict(id=entry['f06RunId'],status='completed',conclusion='success',event='workflow_dispatch',
                head_branch='main',head_sha=entry['sourceForkSha'],head_repository={'full_name':lineage.REPO},
                path=lineage.F06_PATH,run_attempt=entry['f06RunAttempt'],
                display_title=f"F06/{entry['reservationId']}/{entry['versionCode']}/{entry['sourceForkSha']}")


def pin_signed(path, record, entry):
    path.write_text(json.dumps(record,sort_keys=True)+'\n')
    entry['signedProvenanceSha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    return entry
