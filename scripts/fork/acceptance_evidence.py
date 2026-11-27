#!/usr/bin/env python3
"""Read-only provider and retained-evidence verification for F09/F10.

A live audit is bound to an independently successful F08 attempt, its provider
artifact ID and raw archive digest, current tag/ref/assets, and committed review
and signing policy. Retained replay is deliberately not fresh hosted evidence.
"""
from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import zipfile

import event_journal as journal
import f07_release as publication
import f08_qualification as f08
import release_lineage as lineage

REPO = publication.REPO
ROOT = publication.ROOT
F08_PATH = '.github/workflows/fork-f08-release-qualification.yml'
MAX_REPORT = 512 * 1024
MAX_AUDIT_ZIP = 2 * MAX_REPORT
REF_FIELDS = {'tag', 'runId', 'runAttempt', 'artifactId'}


class Refused(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def request(path):
    require(path.startswith('/') and '..' not in path and '\\' not in path, 'AUDIT_API_PATH_INVALID')
    return publication.api(f'repos/{REPO}{path}')


def local_head(root=ROOT):
    """Validate a clean full-history local checkout, without claiming live main."""
    for args in (('remote', 'get-url', '--all', 'origin'), ('remote', 'get-url', '--push', '--all', 'origin')):
        origin = lineage.git(root, *args).decode().strip()
        require(origin in ('https://github.com/'+REPO, 'https://github.com/'+REPO+'.git',
                           'git@github.com:'+REPO, 'git@github.com:'+REPO+'.git'), 'AUDIT_ORIGIN_MISMATCH')
    require(lineage.git(root, 'rev-parse', '--is-shallow-repository').strip() == b'false', 'AUDIT_FULL_HISTORY_REQUIRED')
    head = lineage.git(root, 'rev-parse', 'HEAD').decode().strip()
    require(journal.sha(head), 'AUDIT_LOCAL_HEAD_INVALID')
    require(lineage.git(root, 'status', '--porcelain=v1', '--untracked-files=all') == b'', 'AUDIT_CHECKOUT_DIRTY')
    return head


def exact_main(root=ROOT, get=request):
    """Full-history clean canonical main, no mutation or implicit fetch."""
    head = local_head(root)
    remote = get('/git/ref/heads/main')
    require(remote.get('ref') == 'refs/heads/main' and remote.get('object', {}).get('type') == 'commit' and
            remote['object'].get('sha') == head, 'AUDIT_MAIN_DRIFT')
    return head


def committed_registry(root, head):
    value = journal.strict_json(lineage.git(root, 'show', head+':'+publication.REVIEW_PATH))
    publication.review_continuity(root, head, value)
    return value


def ref_fields(ref):
    require(isinstance(ref, dict) and set(ref) == REF_FIELDS and
            isinstance(ref['tag'], str) and publication.TAG.fullmatch(ref['tag']) and
            all(lineage.positive(ref[k]) for k in ('runId', 'runAttempt', 'artifactId')), 'AUDIT_REFERENCE_INVALID')
    return ref


def entry_for(registry, tag):
    rows = [e for e in publication.validated_registry(registry) if e['tag'] == tag]
    require(len(rows) == 1, 'AUDIT_TAG_NOT_REVIEWED')
    return rows[0]


def download_archive(ident, destination, limit):
    require(lineage.positive(ident) and not destination.exists() and not destination.is_symlink(), 'AUDIT_DOWNLOAD_DESTINATION_INVALID')
    with destination.open('xb') as out:
        p = subprocess.run(['gh', 'api', f'repos/{REPO}/actions/artifacts/{ident}/zip'],
                           stdout=out, stderr=subprocess.PIPE, timeout=240, check=False)
    require(p.returncode == 0 and 0 < destination.stat().st_size <= limit, 'AUDIT_ARCHIVE_DOWNLOAD_FAILED_OR_OVERSIZED')


def read_audit_zip(path, digest):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_AUDIT_ZIP and
            lineage.sha256(digest) and publication.digest(path) == digest, 'AUDIT_ZIP_DIGEST_MISMATCH')
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        require(len(infos) == 1, 'AUDIT_ZIP_MEMBER_COUNT_INVALID')
        row = infos[0]
        require(row.filename == 'qualification.json' and not row.is_dir() and
                stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG) and
                not row.flag_bits & 1 and 0 < row.file_size <= MAX_REPORT, 'AUDIT_ZIP_MEMBER_INVALID')
        with z.open(row) as stream:
            raw = stream.read(MAX_REPORT+1)
        require(len(raw) == row.file_size, 'AUDIT_ZIP_MEMBER_SIZE_DRIFT')
    report = journal.strict_json(raw)
    require(isinstance(report, dict), 'AUDIT_REPORT_INVALID')
    return report


def live_assets(release):
    require(isinstance(release, dict) and lineage.positive(release.get('id')) and
            isinstance(release.get('assets'), list) and 1 <= len(release['assets']) <= publication.MAX_APKS+3,
            'AUDIT_RELEASE_ASSETS_INVALID')
    result, ids = {}, set()
    for row in release['assets']:
        require(isinstance(row, dict) and isinstance(row.get('name'), str) and
                lineage.positive(row.get('id')) and row['id'] not in ids and row['name'] not in result and
                journal.integer(row.get('size'), 1, publication.MAX_ARTIFACT_BYTES) and
                isinstance(row.get('digest'), str) and re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest']),
                'AUDIT_RELEASE_ASSET_METADATA_INVALID')
        result[row['name']] = {k: row[k] for k in ('id', 'size', 'digest')}
        ids.add(row['id'])
    return result


def verify_report(report, entry, ref, run, artifact, release, tag_ref, *, root, head):
    """Require exact current release facts; never accept an uploaded JSON assertion."""
    ref_fields(ref)
    require(ref['tag']==entry['tag'], 'AUDIT_REFERENCE_TAG_DRIFT')
    require(isinstance(run, dict) and journal.sha(run.get('head_sha')), 'AUDIT_RUN_HEAD_INVALID')
    lineage.run_identity(run, ref['runId'], run['head_sha'], F08_PATH, ref['runAttempt'])
    require(run.get('display_title') == 'F08/'+entry['tag'] and
            lineage.ancestor(root, run['head_sha'], head), 'AUDIT_RUN_SOURCE_OR_TITLE_MISMATCH')
    # The audited source must itself contain the identical reviewed candidate.
    historical = journal.strict_json(lineage.git(root, 'show', run['head_sha']+':'+publication.REVIEW_PATH))
    require(entry_for(historical, entry['tag']) == entry, 'AUDIT_HISTORICAL_REVIEW_DRIFT')
    certificate = entry['certificateSha256']
    lineage.signer_continuity(root, head, certificate)
    for revision in (run['head_sha'], head):
        policy = lineage.policy_at(root, revision)
        reserved = lineage.reviewed_reservation(policy, entry['reservationId'], entry['versionCode'])
        require(policy['certificateSha256'] == certificate and
                all(reserved[k] == entry[v] for k, v in (('sourceCommit', 'sourceMergedSha'),
                    ('sourceTree', 'sourceTree'), ('channel', 'channel'))), 'AUDIT_SIGNING_RESERVATION_DRIFT')
        lineage.committed_source(root, reserved, revision)
    require(isinstance(artifact, dict) and isinstance(artifact.get('digest'), str) and
            artifact['digest'].startswith('sha256:'), 'AUDIT_ARTIFACT_DIGEST_MISSING')
    lineage.artifact_identity(artifact, ref['artifactId'], artifact['digest'][7:], ref['runId'], run['head_sha'],
                              f"fork-f08-published-release-audit-{ref['runId']}-{ref['runAttempt']}")
    require(artifact['size_in_bytes'] <= MAX_AUDIT_ZIP, 'AUDIT_ARTIFACT_TOO_LARGE')
    require(isinstance(report, dict) and report.get('schemaVersion') == 2 and
            report.get('repository') == REPO and report.get('status') == 'f08-published-artifacts-verified' and
            report.get('managerPackage') == publication.PACKAGE and
            report.get('forkMainAuditSha') == run['head_sha'] and
            report.get('f08RunId') == ref['runId'] and report.get('f08RunAttempt') == ref['runAttempt'] and
            report.get('reviewDigest') == lineage.digest(entry) and
            all(report.get(k) == entry[k] for k in ('tag', 'f06RunId', 'f06RunAttempt', 'reservationId',
                'sourceTree', 'sourceMergedSha', 'signedProvenanceSha256', 'certificateSha256')) and
            all(report.get(k) is True for k in ('reviewedCompatibility', 'signedApksReverified', 'publishedAssetIntegrity',
                'githubAssetDigestCoverageComplete', 'originalProviderArchiveDigestsVerified')) and
            all(report.get(k) is False for k in ('deviceQualified', 'rootDaemonAuthorized', 'releaseBuildPerformed')),
            'AUDIT_REPORT_SOURCE_OR_SCOPE_DRIFT')
    require(isinstance(release, dict) and release.get('tag_name') == entry['tag'] and
            release.get('id') == report.get('publishedReleaseId') and release.get('draft') is False and
            release.get('prerelease') is (entry['channel'] == 'beta') and
            release.get('target_commitish') == entry['sourceMergedSha'] and
            release.get('body') == publication.release_notes(entry), 'AUDIT_LIVE_RELEASE_IDENTITY_DRIFT')
    journal.utc(release['published_at'])
    require(isinstance(tag_ref, dict) and tag_ref.get('ref') == 'refs/tags/'+entry['tag'] and
            tag_ref.get('object', {}).get('type') == 'commit' and
            tag_ref['object'].get('sha') == entry['sourceMergedSha'], 'AUDIT_LIVE_TAG_DRIFT')
    assets = live_assets(release)
    require(report.get('githubAssets') == assets and report.get('githubAssetDigestsChecked') == len(assets), 'AUDIT_LIVE_ASSET_DRIFT')
    apks = report.get('apks')
    require(isinstance(apks, list) and 1 <= len(apks) <= publication.MAX_APKS, 'AUDIT_APK_ROWS_INVALID')
    names, abis = set(), set()
    for row in apks:
        require(isinstance(row, dict) and set(row) == {'fileName', 'sha256', 'versionCode', 'abi'} and
                isinstance(row['fileName'], str), 'AUDIT_APK_ROW_INVALID')
        m = publication.APK.fullmatch(row['fileName'])
        require(m and row['versionCode'] == entry['versionCode'] == int(m.group(2)) and row['abi'] == m.group(3) and
                row['fileName'] not in names and row['abi'] not in abis and lineage.sha256(row['sha256']) and
                assets.get(row['fileName'], {}).get('digest') == 'sha256:'+row['sha256'], 'AUDIT_APK_IDENTITY_DRIFT')
        names.add(row['fileName']); abis.add(row['abi'])
    require(set(assets) == names | {'manager-compatibility.json', 'f07-release-provenance.json', 'f06-signed-provenance.json'},
            'AUDIT_RELEASE_MEMBER_SET_DRIFT')
    require(assets['f06-signed-provenance.json']['digest'] == 'sha256:'+entry['signedProvenanceSha256'], 'AUDIT_SIGNED_REPORT_DIGEST_DRIFT')
    return report


def provider_snapshot(ref, run, artifact, release, tag_ref):
    """Retain only security-relevant provider fields (not counters or actor data)."""
    run = {k:run.get(k) for k in ('id','event','head_branch','head_sha','head_repository','status','conclusion','run_attempt','path','display_title')}
    run['head_repository'] = {'full_name': (run['head_repository'] or {}).get('full_name')}
    artifact = {k:artifact.get(k) for k in ('id','name','digest','expired','size_in_bytes','workflow_run')}
    artifact['workflow_run'] = {k:(artifact['workflow_run'] or {}).get(k) for k in ('id','head_sha')}
    release = {k:release.get(k) for k in ('id','tag_name','draft','prerelease','target_commitish','published_at','body','author','assets')}
    release['author'] = {'login': (release['author'] or {}).get('login')}
    release['assets'] = sorted(({k:a.get(k) for k in ('id','name','size','digest')} for a in release['assets']), key=lambda a:a['name'])
    tag_ref = {'ref': tag_ref.get('ref'), 'object': {k:tag_ref.get('object',{}).get(k) for k in ('type','sha')}}
    return dict(reference=ref, run=run, artifact=artifact, release=release, tagRef=tag_ref)


def fetch_live_audit(ref, registry, *, root=ROOT, head, get=request, download=download_archive, retain=None):
    ref_fields(ref); entry = entry_for(registry, ref['tag'])
    run = get('/actions/runs/'+str(ref['runId']))
    meta = get('/actions/artifacts/'+str(ref['artifactId']))
    require(isinstance(meta, dict) and isinstance(meta.get('digest'), str) and
            re.fullmatch(r'sha256:[0-9a-f]{64}', meta['digest']) and meta.get('expired') is False and
            journal.integer(meta.get('size_in_bytes'), 1, MAX_AUDIT_ZIP), 'AUDIT_ARTIFACT_UNAVAILABLE')
    release = get('/releases/tags/'+entry['tag']); tag_ref = get('/git/ref/tags/'+entry['tag'])
    with tempfile.TemporaryDirectory(prefix='bakasu-f08-readback-') as folder:
        archive = Path(folder)/'audit.zip'
        download(ref['artifactId'], archive, MAX_AUDIT_ZIP)
        report = read_audit_zip(archive, meta['digest'][7:])
        require(archive.stat().st_size == meta['size_in_bytes'], 'AUDIT_ARTIFACT_SIZE_DRIFT')
        verify_report(report, entry, ref, run, meta, release, tag_ref, root=root, head=head)
        # Detect races/retags/reuploads during retrieval.
        snapshot = provider_snapshot(ref,run,meta,release,tag_ref)
        after = provider_snapshot(ref, get('/actions/runs/'+str(ref['runId'])), get('/actions/artifacts/'+str(ref['artifactId'])),
                                  get('/releases/tags/'+entry['tag']), get('/git/ref/tags/'+entry['tag']))
        require(after == snapshot, 'AUDIT_PROVIDER_CHANGED_DURING_READBACK')
        if retain is not None:
            retain(archive, snapshot)
    return dict(reference=ref, artifactSha256=meta['digest'][7:], report=report,
                releaseId=release['id'], publishedAt=release['published_at'])


def private_directory(path):
    path = Path(path).expanduser().absolute()
    require(path.is_dir() and path.resolve() == path and not path.is_symlink() and
            path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0,
            'AUDIT_OUTPUT_DIRECTORY_NOT_PRIVATE')
    return path


def publish_noreplace(source, destination):
    """Publish a fully synced file atomically without replacing any destination.

    Android/Termux Python can omit os.link even on a filesystem supporting
    Linux renameat2. RENAME_NOREPLACE provides the same exclusive publication
    guarantee without a hard link. Never fall back to check-then-rename or an
    observable partial destination when the kernel/filesystem lacks support.
    """
    link = getattr(os, 'link', None)
    if link is not None:
        try:
            link(source, destination, follow_symlinks=False)
            return
        except OSError as error:
            if error.errno not in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EPERM):
                raise
    try:
        import ctypes
        rename = ctypes.CDLL(None, use_errno=True).renameat2
    except (ImportError, AttributeError, OSError) as error:
        raise Refused('AUDIT_EXCLUSIVE_PUBLICATION_UNAVAILABLE') from error
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    # Linux UAPI: AT_FDCWD=-100, RENAME_NOREPLACE=1. Paths are absolute.
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        if code in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            raise Refused('AUDIT_EXCLUSIVE_PUBLICATION_UNAVAILABLE')
        raise OSError(code, os.strerror(code), os.fspath(destination))


def write_private(path, obj):
    path = Path(path).expanduser().absolute()
    parent = private_directory(path.parent)
    raw = journal.canonical(obj)
    require(len(raw) <= 8_000_000 and not path.exists() and not path.is_symlink(), 'AUDIT_OUTPUT_ALREADY_EXISTS_OR_OVERSIZED')
    fd, name = tempfile.mkstemp(prefix='.audit-', dir=parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        try:
            publish_noreplace(name, path)
        except FileExistsError as error:
            raise Refused('AUDIT_OUTPUT_ALREADY_EXISTS_OR_OVERSIZED') from error
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)
    return hashlib.sha256(raw).hexdigest()
