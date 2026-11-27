#!/usr/bin/env python3
"""F10 read-only cross-channel release/journal reconciliation and durable replay.

Never dispatch, reserve a version, sign, publish, delete, retag, install or
modify the journal. Archived provider observations are historical evidence;
offline replay is NOT a fresh F08 audit or device acceptance.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

import acceptance_evidence as ev
import event_journal as journal
import f06_signing as signing
import f07_release as publication
import f08_qualification as f08
from journal_store import LocalJournal
import release_lineage as lineage

ROOT = ev.ROOT
MAX_RETAINED_BYTES = 5 * 1024**3
ASSET_NAMES = {'manager-compatibility.json','f07-release-provenance.json','f06-signed-provenance.json'}


class Refused(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def inventory(get=ev.request):
    """Complete bounded pagination; duplicate or truncated evidence refuses."""
    rows, ids, tags = [], set(), set()
    for page in range(1, publication.MAX_RELEASE_PAGES+1):
        data = get(f'/releases?per_page=100&page={page}')
        require(isinstance(data,list) and len(data)<=100,'REPLAY_RELEASE_PAGE_INVALID')
        for row in data:
            require(isinstance(row,dict) and lineage.positive(row.get('id')) and row['id'] not in ids and
                    isinstance(row.get('tag_name'),str) and row['tag_name'] not in tags and
                    type(row.get('draft')) is bool and isinstance(row.get('assets'),list), 'REPLAY_RELEASE_INVENTORY_AMBIGUOUS')
            require(all(isinstance(a,dict) and isinstance(a.get('name'),str) for a in row['assets']), 'REPLAY_RELEASE_ASSET_NAME_INVALID')
            ids.add(row['id']);tags.add(row['tag_name']);rows.append(row)
        if len(data)<100:
            return rows
    raise Refused('REPLAY_RELEASE_HISTORY_TRUNCATED')


def validate_journal(state, policy, registry):
    journal.validate(state); lineage.signing_policy(policy)
    exports = {}
    for key, row in state['events'].items():
        if row['reservation'] is not None:
            exported = lineage.export_reservation(state,key)
            exports[exported['reservationId']] = exported
    approved = {row['reservationId']:row for row in policy['approvedReservations']}
    require(all(exports.get(k)==v for k,v in approved.items()), 'REPLAY_REVIEWED_RESERVATION_ABSENT_OR_CHANGED_IN_JOURNAL')
    for entry in publication.validated_registry(registry):
        reserved = approved.get(entry['reservationId'])
        require(reserved is not None and policy['certificateSha256']==entry['certificateSha256'] and
                all(reserved[k]==entry[v] for k,v in (('versionCode','versionCode'),('channel','channel'),
                    ('sourceCommit','sourceMergedSha'),('sourceTree','sourceTree'))), 'REPLAY_PUBLICATION_WITHOUT_EXACT_SIGNING_RESERVATION')
    return {'revision':state['revision'],'checkpoint':state['checkpoint'],'stateSha256':lineage.digest(state),
            'eventCount':len(state['events']),'nextVersion':state['nextVersion'],'reservedCount':len(exports),
            'approvedCount':len(approved),'unreviewedReservations':sorted(set(exports)-set(approved)),
            'unresolvedIntents':sorted(key for key,row in state['events'].items() if row['attempts'] and row['attempts'][-1]['state'] in ('intent','observed'))}


def reconcile_releases(registry, releases, verified, state=None):
    """Compare observed public release IDs, exact assets and monotonic timeline."""
    by_tag = {row['tag']:row for row in publication.validated_registry(registry)}
    seen, ids, timeline, rows = set(), set(), [], []
    ignored = 0
    for release in releases:
        require(isinstance(release,dict) and lineage.positive(release.get('id')) and release['id'] not in ids and
                isinstance(release.get('tag_name'),str) and release['tag_name'] not in seen and
                type(release.get('draft')) is bool and isinstance(release.get('assets'),list), 'REPLAY_RELEASE_INVENTORY_INVALID')
        tag = release['tag_name'];seen.add(tag);ids.add(release['id'])
        require(all(isinstance(a,dict) and isinstance(a.get('name'),str) for a in release['assets']), 'REPLAY_RELEASE_ASSET_INVALID')
        apks = [a for a in release['assets'] if a['name'].lower().endswith('.apk')]
        if not tag.startswith('f07-v') and not apks:
            ignored += 1; continue
        require(tag in by_tag, 'REPLAY_UNREVIEWED_FORK_APK_OR_RELEASE')
        entry = by_tag[tag]
        require(release.get('target_commitish') == entry['sourceMergedSha'] and
                release.get('prerelease') is (entry['channel']=='beta') and
                release.get('body') == publication.release_notes(entry), 'REPLAY_RELEASE_REVIEW_IDENTITY_DRIFT')
        if release['draft']:
            require(tag not in verified, 'REPLAY_AUDIT_FOR_UNPUBLISHED_RELEASE')
            rows.append({'tag':tag,'versionCode':entry['versionCode'],'channel':entry['channel'], 'releaseId':release['id'], 'status':'DRAFT_REQUIRES_REVIEWED_RESUME'})
            continue
        assets = ev.live_assets(release);names = set();abis = set()
        for a in apks:
            m = publication.APK.fullmatch(a['name'])
            require(m and int(m.group(2))==entry['versionCode'] and m.group(3) not in abis,'REPLAY_RELEASE_APK_VERSION_OR_ABI_DRIFT')
            names.add(a['name']);abis.add(m.group(3))
        require(names and set(assets)==names|ASSET_NAMES and
                assets['f06-signed-provenance.json']['digest']=='sha256:'+entry['signedProvenanceSha256'], 'REPLAY_PUBLISHED_ASSET_INVENTORY_DRIFT')
        time = journal.utc(release['published_at']);timeline.append((time,entry['versionCode'],tag))
        audit = verified.get(tag)
        if audit is not None:
            report = audit['report']
            require(audit['releaseId']==release['id'] and report['githubAssets']==assets and
                    audit['publishedAt']==release['published_at'] and report['reviewDigest']==lineage.digest(entry), 'REPLAY_LIVE_AUDIT_INVENTORY_DRIFT')
        rows.append({'tag':tag,'versionCode':entry['versionCode'],'channel':entry['channel'],'releaseId':release['id'],
                     'status':'LIVE_F08_EVIDENCE_VERIFIED' if audit else 'PUBLISHED_F08_EVIDENCE_PENDING',
                     'audit':audit['reference'] if audit else None,'auditSha256':audit['artifactSha256'] if audit else None})
    require(set(verified)<={tag for _,_,tag in timeline}, 'REPLAY_AUDIT_FOR_MISSING_PUBLIC_RELEASE')
    timeline.sort()
    require(all(a[0]<b[0] and a[1]<b[1] for a,b in zip(timeline,timeline[1:])), 'REPLAY_CROSS_CHANNEL_VERSION_ORDER_AMBIGUOUS_OR_REGRESSED')
    floor = max((row[1] for row in timeline),default=0)
    if state is not None:
        require(state['nextVersion']>floor, 'REPLAY_JOURNAL_ALLOCATOR_BELOW_PUBLISHED_FLOOR')
    rows.extend({'tag':e['tag'],'versionCode':e['versionCode'],'channel':e['channel'],'status':'REVIEWED_VERSION_BELOW_PUBLISHED_FLOOR' if e['versionCode']<=floor else 'REVIEWED_NOT_PUBLISHED'} for e in by_tag.values() if e['tag'] not in seen)
    return {'releaseRows':sorted(rows,key=lambda r:r['versionCode']), 'publishedVersionFloor':floor,
            'publishedCount':len(timeline),'liveF08Count':len(verified),'ignoredNonManagerReleases':ignored,
            'versionOrderVerified':True,'versionOrderHasPublishedEvidence':bool(timeline)}


def scheduled_observation(root,head,get):
    path='.github/workflows/fork-upstream-discovery.yml'
    response=get('/actions/workflows/fork-upstream-discovery.yml/runs?event=schedule&status=completed&per_page=20')
    require(isinstance(response,dict) and isinstance(response.get('workflow_runs'),list) and len(response['workflow_runs'])<=20,'REPLAY_SCHEDULE_RESPONSE_INVALID')
    for run in response['workflow_runs']:
        if (isinstance(run,dict) and lineage.positive(run.get('id')) and run.get('event')=='schedule' and
                run.get('head_branch')=='main' and (run.get('head_repository') or {}).get('full_name')==ev.REPO and
                str(run.get('path','')).split('@',1)[0].removeprefix('/') in (path,ev.REPO+'/'+path) and
                run.get('status')=='completed' and run.get('conclusion')=='success' and journal.sha(run.get('head_sha')) and
                lineage.ancestor(root,run['head_sha'],head)):
            return {'runId':run['id'],'sourceCommit':run['head_sha'],'createdAt':journal.timestamp(journal.utc(run['created_at']))}
    return None


def hosted_required(root,head,get):
    policy = journal.strict_json(lineage.git(root,'show',head+':config/delivery-required-ci.json'))
    required = {row['workflow_id']:row['name'] for row in policy['required_workflows']}
    require(len(required)==len(policy['required_workflows']) and required,'REPLAY_REQUIRED_WORKFLOW_POLICY_INVALID')
    found={};seen=set();total=None
    for page in range(1,11):
        response=get(f'/actions/runs?head_sha={head}&event=push&per_page=100&page={page}')
        require(isinstance(response,dict) and journal.integer(response.get('total_count'),0,1000) and
                isinstance(response.get('workflow_runs'),list) and len(response['workflow_runs'])<=100,'REPLAY_CI_RUN_LIST_INVALID')
        total=response['total_count'] if total is None else total
        require(total==response['total_count'],'REPLAY_CI_RUN_COUNT_DRIFT')
        for row in response['workflow_runs']:
            require(lineage.positive(row.get('id')) and row['id'] not in seen,'REPLAY_CI_RUN_DUPLICATE');seen.add(row['id'])
            wid=row.get('workflow_id')
            if wid not in required:continue
            require(row.get('head_sha')==head and row.get('head_branch')=='main' and row.get('event')=='push' and row.get('name')==required[wid] and
                    (row.get('head_repository') or {}).get('full_name')==ev.REPO and lineage.positive(row.get('run_attempt')),
                    'REPLAY_CI_RUN_SOURCE_DRIFT')
            if wid not in found or row['id']>found[wid]['id']:found[wid]=row
        if len(seen)==total:break
        require(response['workflow_runs'] and len(seen)<total,'REPLAY_CI_RUN_LIST_INCOMPLETE')
    else:raise Refused('REPLAY_CI_RUN_LIST_TRUNCATED')
    return [{'workflowId':wid,'name':name,'runId':found[wid]['id'] if wid in found else None,
             'status':'PASS' if wid in found and found[wid].get('status')=='completed' and found[wid].get('conclusion')=='success'
             else 'FAIL' if wid in found and found[wid].get('status')=='completed' else 'PENDING'} for wid,name in sorted(required.items())]


def audit(root,head,registry,policy,state,refs,*,get=ev.request,fetch=ev.fetch_live_audit):
    lineage.signing_policy(policy)
    if policy['certificateSha256'] is not None:lineage.signer_continuity(root,head,policy['certificateSha256'])
    signing_rows={r['reservationId']:r for r in policy['approvedReservations']}
    # Even without an owner journal, committed publication review must match signing policy.
    for entry in publication.validated_registry(registry):
        r=signing_rows.get(entry['reservationId']);require(r is not None and policy['certificateSha256']==entry['certificateSha256'] and
            all(r[k]==entry[v] for k,v in (('versionCode','versionCode'),('channel','channel'),('sourceCommit','sourceMergedSha'),('sourceTree','sourceTree'))), 'REPLAY_COMMITTED_RELEASE_RESERVATION_DRIFT')
    for row in signing_rows.values():lineage.committed_source(root,row,head)
    journal_report=validate_journal(state,policy,registry) if state is not None else None
    require(isinstance(refs,list) and len(refs)<=journal.MAX_EVENTS,'REPLAY_AUDIT_REFERENCE_LIST_INVALID')
    verified={}
    for ref in refs:
        ev.ref_fields(ref);require(ref['tag'] not in verified,'REPLAY_DUPLICATE_AUDIT_REFERENCE')
        verified[ref['tag']]=fetch(ref,registry,root=root,head=head,get=get)
    first=inventory(get);result=reconcile_releases(registry,first,verified,state)
    entries={e['tag']:e for e in publication.validated_registry(registry)}
    def tags():
        observed={}
        for release in first:
            tag=release['tag_name']
            if release['draft'] or tag not in entries:continue
            ref=get('/git/ref/tags/'+tag)
            require(ref.get('ref')=='refs/tags/'+tag and ref.get('object',{}).get('type')=='commit' and
                    ref['object'].get('sha')==entries[tag]['sourceMergedSha'],'REPLAY_LIVE_TAG_DRIFT')
            observed[tag]=ref['object']['sha']
        return observed
    tag_snapshot=tags()
    # Only stable fields: download counts and other non-identity counters may change.
    def identity(items):
        return [(r['id'],r['tag_name'],r['draft'],r.get('prerelease'),r.get('target_commitish'),r.get('published_at'),r.get('body'),
                 sorted(((a.get('id'),a['name'],a.get('size'),a.get('digest')) for a in r['assets']),key=lambda a:a[1])) for r in sorted(items,key=lambda r:r['id'])]
    require(identity(first)==identity(inventory(get)) and tags()==tag_snapshot,'REPLAY_RELEASE_INVENTORY_CHANGED_DURING_AUDIT')
    ci=hosted_required(root,head,get); schedule=scheduled_observation(root,head,get)
    # A local journal reservation is not proof of a live build. Verify every
    # reviewed diagnostic run/artifact with its exact provider identity.
    diagnostic=[]
    for row in signing_rows.values():
        try:
            lineage.verify_diagnostic(row,get)
            status='PROVIDER_IDENTITY_VERIFIED'
        except (ValueError, RuntimeError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
            status='UNVERIFIED_REQUIRES_REVIEW'
        diagnostic.append({'reservationId':row['reservationId'],'runId':row['diagnosticRunId'],'status':status})
    all_audited=bool(result['publishedCount']) and result['publishedCount']==result['liveF08Count']
    statuses=[
        ('F01','Fork manager source contract','HOSTED_REQUIRED_VERIFIED' if all(x['status']=='PASS' for x in ci) else 'HOSTED_REQUIRED_PENDING_OR_FAILED'),
        ('F02','Secure module reinstall','PHYSICAL_NEGATIVE_AND_REINSTALL_TESTS_REQUIRED'),
        ('F03','Stable/beta compatibility','SIGNED_CANDIDATE_AND_INSTALLED_KERNEL_TESTS_REQUIRED'),
        ('F04','Upstream discovery','SCHEDULE_OBSERVED_OWNER_JOURNAL_CADENCE_UNVERIFIED' if schedule else 'SCHEDULE_AND_OWNER_JOURNAL_CADENCE_PENDING'),
        ('F05','Source-pinned integration and debug build','REVIEWED_PROMOTIONS_PROVIDER_VERIFIED' if diagnostic and all(x['status']=='PROVIDER_IDENTITY_VERIFIED' for x in diagnostic) and journal_report else 'DIAGNOSTIC_PROMOTION_OR_JOURNAL_PENDING'),
        ('F06','Signed manager qualification','PUBLISHED_SIGNED_ARTIFACTS_HAVE_F08_PROOF' if all_audited else 'PROTECTED_SIGNED_BUILD_AND_PROOF_PENDING'),
        ('F07','Reviewed release publishing','OBSERVED_REVIEWED_PUBLIC_RELEASES' if result['publishedCount'] else 'REVIEWED_PUBLICATION_PENDING'),
        ('F08','Published-release qualification','LIVE_F08_REPORTS_VERIFIED' if all_audited else 'INDEPENDENT_PUBLISHED_AUDIT_PENDING'),
        ('F09','Physical-device and root authorization','F09_INDEPENDENT_PHYSICAL_REVIEW_REQUIRED'),
        ('F10','Durable release/replay and monotonic versioning','JOURNAL_AND_LIVE_VERSION_CHAIN_OBSERVED_REPLAY_REVIEW_REQUIRED' if journal_report and all_audited else 'JOURNAL_OR_PUBLISHED_VERSION_CHAIN_PENDING'),
    ]
    return {'schemaVersion':1,'repository':ev.REPO,'sourceCommit':head,'sourceTree':lineage.git(root,'rev-parse',head+'^{tree}').decode().strip(),
            'status':'R9_FACTUAL_AUDIT_INDEPENDENT_ACCEPTANCE_PENDING','milestones':[dict(id=i,name=n,status=s,accepted=False) for i,n,s in statuses],
            'originalMilestoneCount':10,'fullyAcceptedCount':0,'requiredCi':ci,'scheduledDiscovery':schedule,
            'journal':journal_report,'diagnosticProviderEvidence':diagnostic,'releaseAudit':result,
            'deviceQualified':False,'rootDaemonAuthorized':False,'remoteMutationsPerformed':False}


def download_asset(asset_id,destination):
    require(lineage.positive(asset_id) and not destination.exists() and not destination.is_symlink(),'REPLAY_ASSET_DESTINATION_INVALID')
    with destination.open('xb') as out:
        p=subprocess.run(['gh','api','-H','Accept: application/octet-stream',f'repos/{ev.REPO}/releases/assets/{asset_id}'],
                         stdout=out,stderr=subprocess.PIPE,timeout=240,check=False)
    require(p.returncode==0,'REPLAY_RELEASE_ASSET_DOWNLOAD_FAILED')


def file_inventory(folder):
    files={};size=0
    for p in sorted(folder.rglob('*')):
        require(not p.is_symlink(),'REPLAY_SYMLINK_REFUSED')
        if p.is_dir():continue
        require(p.is_file(),'REPLAY_NONREGULAR_FILE_REFUSED')
        name=p.relative_to(folder).as_posix()
        if name=='manifest.json':continue
        n=p.stat().st_size;size+=n
        require(0<n<=publication.MAX_ARTIFACT_BYTES and size<=MAX_RETAINED_BYTES and len(files)<32,'REPLAY_RETAINED_INVENTORY_LIMIT')
        files[name]={'size':n,'sha256':publication.digest(p)}
    return files


def replay_bundle(folder,registry,*,root,head,sdk,check_inventory=True,checker=f08.check_release):
    folder=ev.private_directory(folder)
    if check_inventory:
        manifest=lineage.read_json(folder/'manifest.json',ev.MAX_REPORT)
        require(manifest.get('schemaVersion')==1 and manifest.get('repository')==ev.REPO and journal.sha(manifest.get('captureHead')) and
                lineage.ancestor(root,manifest['captureHead'],head) and lineage.git(root,'rev-parse',manifest['captureHead']+'^{tree}').decode().strip()==manifest.get('captureTree') and
                manifest.get('files')==file_inventory(folder),'REPLAY_RETAINED_MANIFEST_DRIFT')
    provider=lineage.read_json(folder/'provider.json',ev.MAX_REPORT);ref=ev.ref_fields(provider['reference']);entry=ev.entry_for(registry,ref['tag'])
    artifact=provider['artifact'];report=ev.read_audit_zip(folder/'audit.zip',artifact['digest'][7:])
    require((folder/'audit.zip').stat().st_size==artifact['size_in_bytes'],'REPLAY_AUDIT_ARCHIVE_SIZE_DRIFT')
    ev.verify_report(report,entry,ref,provider['run'],artifact,provider['release'],provider['tagRef'],root=root,head=head)
    f06_provider=lineage.read_json(folder/'f06-provider.json',ev.MAX_REPORT)
    publication.run_identity(f06_provider['run'],entry)
    for kind in ('apk','evidence'):
        meta=f06_provider[kind];lineage.artifact_identity(meta,entry[kind+'ArtifactId'],entry[kind+'ArtifactSha256'],entry['f06RunId'],entry['sourceForkSha'],publication.artifact_name(entry,kind))
        require((folder/('f06-'+kind+'.zip')).stat().st_size==meta['size_in_bytes'],'REPLAY_F06_ARCHIVE_SIZE_DRIFT')
    assets=folder/'assets';require(assets.is_dir() and not assets.is_symlink(),'REPLAY_ASSETS_DIRECTORY_INVALID')
    expected=set(report['githubAssets']);require({p.name for p in assets.iterdir()}==expected,'REPLAY_RETAINED_ASSET_INVENTORY_DRIFT')
    require(set(file_inventory(folder))=={'provider.json','f06-provider.json','audit.zip','f06-apk.zip','f06-evidence.zip'}|{'assets/'+name for name in expected},'REPLAY_UNEXPECTED_RETAINED_FILES')
    for name,meta in report['githubAssets'].items():
        p=assets/name;require(p.is_file() and not p.is_symlink() and p.stat().st_size==meta['size'] and 'sha256:'+publication.digest(p)==meta['digest'],'REPLAY_RETAINED_ASSET_BYTES_DRIFT')
    with tempfile.TemporaryDirectory(prefix='bakasu-retained-replay-') as scratch:
        e=Path(scratch)/'evidence';e.mkdir();apks=Path(scratch)/'apk';apks.mkdir()
        publication.extract_f06_artifact(folder/'f06-evidence.zip',e,'evidence',entry['evidenceArtifactSha256'])
        publication.extract_f06_artifact(folder/'f06-apk.zip',apks,'apk',entry['apkArtifactSha256'])
        signed=publication.read_signed_evidence(e/'f06-signed-provenance.json',entry)
        require(lineage.read_json(e/'f06-promoted-source.json')==signed['source'],'REPLAY_RETAINED_SOURCE_REPORT_DRIFT')
        actual=checker(entry['tag'],provider['release'],registry,lineage.read_json(assets/'f07-release-provenance.json'),f06_provider['run'],
                       lineage.read_json(assets/'manager-compatibility.json'),signed,assets,head=provider['run']['head_sha'],sdk=sdk,
                       tag_ref=provider['tagRef'],ancestor=lambda a,b:lineage.ancestor(root,a,b),source_root=root)
        require(all(report.get(k)==v for k,v in actual.items() if k!='schemaVersion') and
                {p.name for p in apks.iterdir()}=={r['fileName'] for r in report['apks']} and
                all(publication.digest(apks/r['fileName'])==r['sha256'] for r in report['apks']), 'REPLAY_RETAINED_SIGNED_APK_OR_REPORT_DRIFT')
    return {'schemaVersion':1,'repository':ev.REPO,'status':'RETAINED_RELEASE_BYTES_AND_SIGNATURES_REVERIFIED_NOT_FRESH_F08',
            'tag':entry['tag'],'reference':ref,'auditArchiveSha256':artifact['digest'][7:],'sourceTree':entry['sourceTree'],
            'versionCode':entry['versionCode'],'certificateSha256':entry['certificateSha256'],'recordedReleaseId':provider['release']['id'],
            'recordedAssetCount':len(expected),'localReviewHead':head,'freshProviderQualification':False,'deviceQualified':False,'rootDaemonAuthorized':False}


def retain_bundle(folder,ref,registry,*,root,head,sdk,get=ev.request,download=ev.download_archive,asset_download=download_asset,checker=f08.check_release):
    folder=Path(folder).expanduser().absolute();ev.private_directory(folder.parent);folder.mkdir(mode=0o700,exist_ok=False)
    try:
        def retain(archive,provider):
            shutil.copyfile(archive,folder/'audit.zip');ev.write_private(folder/'provider.json',provider)
        verified=ev.fetch_live_audit(ref,registry,root=root,head=head,get=get,download=download,retain=retain)
        entry=ev.entry_for(registry,ref['tag']);run=get('/actions/runs/'+str(entry['f06RunId']));publication.run_identity(run,entry)
        meta={'run':run}
        for kind in ('apk','evidence'):
            data=get('/actions/artifacts/'+str(entry[kind+'ArtifactId']))
            lineage.artifact_identity(data,entry[kind+'ArtifactId'],entry[kind+'ArtifactSha256'],entry['f06RunId'],entry['sourceForkSha'],publication.artifact_name(entry,kind))
            require(data['size_in_bytes']<=publication.MAX_ARTIFACT_BYTES,'REPLAY_ORIGINAL_ARCHIVE_TOO_LARGE');meta[kind]=data
        total=sum(m['size_in_bytes'] for k,m in meta.items() if k!='run')+sum(m['size'] for m in verified['report']['githubAssets'].values())
        require(total<=MAX_RETAINED_BYTES,'REPLAY_RETAINED_TOTAL_TOO_LARGE')
        # Store only needed public metadata; no auth headers or transient redirect URLs.
        runkeys=('id','event','head_branch','head_sha','head_repository','status','conclusion','run_attempt','path','display_title')
        meta['run']={k:run.get(k) for k in runkeys};meta['run']['head_repository']={'full_name':run['head_repository']['full_name']}
        for kind in ('apk','evidence'):
            data=meta[kind];meta[kind]={k:data.get(k) for k in ('id','name','digest','expired','size_in_bytes','workflow_run')};meta[kind]['workflow_run']={k:data['workflow_run'].get(k) for k in ('id','head_sha')}
            download(entry[kind+'ArtifactId'],folder/('f06-'+kind+'.zip'),publication.MAX_ARTIFACT_BYTES)
        ev.write_private(folder/'f06-provider.json',meta)
        assets=folder/'assets';assets.mkdir(mode=0o700)
        for name,info in verified['report']['githubAssets'].items():asset_download(info['id'],assets/name)
        result=replay_bundle(folder,registry,root=root,head=head,sdk=sdk,check_inventory=False,checker=checker)
        # Repeat the live F08 source/asset observation before finalizing; raw
        # original F06 hashes are independently reverified by replay_bundle.
        final=ev.fetch_live_audit(ref,registry,root=root,head=head,get=get,download=download)
        require(final==verified and ev.exact_main(root,get)==head,'REPLAY_PROVIDER_CHANGED_BEFORE_RETENTION')
        manifest={'schemaVersion':1,'repository':ev.REPO,'captureHead':head,'captureTree':lineage.git(root,'rev-parse',head+'^{tree}').decode().strip(),
                  'capturedAt':journal.timestamp(datetime.now(timezone.utc)),'files':file_inventory(folder)}
        # Flush every retained file before making the completion manifest visible.
        for rel in manifest['files']:
            with (folder/rel).open('rb') as stream:os.fsync(stream.fileno())
        fd=os.open(assets,os.O_DIRECTORY|os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
        ev.write_private(folder/'manifest.json',manifest)
        fd=os.open(folder.parent,os.O_DIRECTORY|os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
        result['status']='RETAINED_RELEASE_ARCHIVE_VERIFIED';result['manifestSha256']=publication.digest(folder/'manifest.json');return result
    except BaseException:
        # Only the newly created private output directory is ours to remove.
        shutil.rmtree(folder)
        raise


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('audit');a.add_argument('--journal',type=Path);a.add_argument('--references',type=Path);a.add_argument('--output',type=Path,required=True)
    a=sub.add_parser('retain');a.add_argument('--reference',type=Path,required=True);a.add_argument('--folder',type=Path,required=True);a.add_argument('--sdk',type=Path,required=True);a.add_argument('--output',type=Path,required=True)
    a=sub.add_parser('replay');a.add_argument('--folder',type=Path,required=True);a.add_argument('--sdk',type=Path,required=True);a.add_argument('--output',type=Path,required=True)
    args=p.parse_args(argv)
    try:
        ev.private_directory(args.output.expanduser().absolute().parent)
        require(not args.output.exists() and not args.output.is_symlink(),'REPLAY_REPORT_ALREADY_EXISTS')
        head=ev.local_head() if args.command=='replay' else ev.exact_main();registry=ev.committed_registry(ROOT,head)
        if args.command=='audit':
            state=LocalJournal(args.journal).read() if args.journal else None
            refs=lineage.read_json(args.references,2*1024*1024) if args.references else {'schemaVersion':1,'references':[]}
            require(set(refs)=={'schemaVersion','references'} and refs['schemaVersion']==1,'REPLAY_REFERENCE_INDEX_SCHEMA_INVALID')
            result=audit(ROOT,head,registry,lineage.policy_at(ROOT,head),state,refs['references'])
            require(ev.exact_main()==head,'REPLAY_MAIN_DRIFT_DURING_AUDIT')
        elif args.command=='retain':result=retain_bundle(args.folder,lineage.read_json(args.reference),registry,root=ROOT,head=head,sdk=args.sdk)
        else:result=replay_bundle(args.folder,registry,root=ROOT,head=head,sdk=args.sdk)
        checksum=ev.write_private(args.output,result);print('BK_GAP05_RELEASE_EVIDENCE_WRITTEN sha256='+checksum+' status='+result['status']);return 1 if any(x['status']=='FAIL' for x in result.get('requiredCi',[])) else 0
    except (ValueError,RuntimeError,OSError,KeyError,TypeError,AttributeError,subprocess.SubprocessError,zipfile.BadZipFile) as exc:
        code=str(exc) if isinstance(exc,(Refused,ev.Refused,lineage.Refused,publication.Refused,journal.JournalError,f08.Refused,signing.Refused)) and re.fullmatch(r'[A-Za-z0-9_]+',str(exc)) else type(exc).__name__
        print('BK_GAP05_RELEASE_REFUSED '+code,file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
