#!/usr/bin/env python3
"""F08 independently qualify a published fork manager release (read-only).

No publish, install, device, key material, GitHub mutation, or derived review
approval. An F07 release never counts as device-authorized merely by passing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import release_lineage as lineage
import f07_release as publication

from f06_signing import apk_metadata, sdk_tool, NATIVE_ABIS, Refused as SigningRefused
from f07_release import REPO, RUN_PATH, PACKAGE, APK, TAG, SHA, reviewed_entry, Refused as F07Refused

ROOT = Path(__file__).resolve().parents[2]
MAX_JSON = 512 * 1024
MAX_APKS = 10
FINGERPRINT = re.compile(r'[0-9a-f]{64}\Z')


class Refused(RuntimeError):
    pass


def require(ok: object, reason: str) -> None:
    if not ok:
        raise Refused(reason)


def read_json_file(path: Path, *, max_bytes: int = MAX_JSON) -> dict:
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= max_bytes,
            'F08_UNSAFE_OR_OVERSIZED_JSON_'+path.name)
    try:
        obj = lineage.read_json(path,max_bytes)
    except (ValueError, UnicodeError):
        raise Refused('F08_INVALID_JSON_'+path.name) from None
    require(isinstance(obj, dict), 'F08_JSON_OBJECT_REQUIRED_'+path.name)
    return obj


def hash_file(path: Path) -> str:
    with path.open('rb') as inp:
        return hashlib.file_digest(inp, 'sha256').hexdigest()


def exact_main() -> str:
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('GITHUB_REPOSITORY') == REPO and
            os.environ.get('GITHUB_REF') == 'refs/heads/main',
            'F08_HOSTED_FORK_MAIN_ONLY')
    p = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                       text=True, capture_output=True, timeout=25, check=False)
    require(p.returncode == 0 and SHA.fullmatch(p.stdout.strip()) and
            p.stdout.strip() == os.environ.get('GITHUB_SHA'),
            'F08_GITHUB_CHECKOUT_SHA_DRIFT')
    return p.stdout.strip()


def committed_ancestor(merged: str, head: str) -> bool:
    require(SHA.fullmatch(merged) and SHA.fullmatch(head), 'F08_COMMIT_SHA_INVALID')
    p = subprocess.run(['git', '-C', str(ROOT), 'merge-base', '--is-ancestor', merged, head],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=25, check=False, env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1'))
    return p.returncode == 0


def check_release(tag: str, release: dict, registry: dict, provenance: dict,
                  run: dict, compat: dict, f06: dict, assets: Path, *, head: str,
                  sdk: Path, tag_ref: dict, ancestor=committed_ancestor,
                  apk_checker=apk_metadata, source_root=ROOT) -> dict:
    require(isinstance(tag, str) and TAG.fullmatch(tag) and SHA.fullmatch(head),
            'F08_TAG_OR_HEAD_INVALID')
    require(isinstance(provenance, dict) and provenance.get('schemaVersion') == 1
            and provenance.get('repository') == REPO and
            provenance.get('status') == 'release-candidate-reviewed' and
            provenance.get('releasePublished') is False and
            provenance.get('tag') == tag and provenance.get('channel') in ('beta', 'stable') and
            type(provenance.get('f06RunId')) is int and provenance['f06RunId'] > 0 and
            SHA.fullmatch(str(provenance.get('sourceMergedSha', ''))) and
            SHA.fullmatch(str(provenance.get('sourceForkSha', ''))) and
            FINGERPRINT.fullmatch(str(provenance.get('certificateSha256', ''))),
            'F08_F07_PROVENANCE_INVALID')
    try:
        entry = reviewed_entry(registry, provenance['f06RunId'], tag, provenance['channel'])
    except F07Refused:
        raise Refused('F08_REVIEWED_CANDIDATE_MISSING_OR_INVALID') from None
    require(all(entry[k] == provenance[k] for k in
                ('f06RunId', 'f06RunAttempt', 'tag', 'channel', 'sourceMergedSha', 'sourceForkSha',
                 'sourceTree', 'reservationId', 'signedProvenanceSha256', 'certificateSha256')), 'F08_REVIEW_REGISTRY_PROVENANCE_MISMATCH')
    require(ancestor(entry['sourceMergedSha'], head), 'F08_RELEASE_SOURCE_NOT_ON_MAIN')
    require(provenance.get('reviewDigest')==lineage.digest(entry),'F08_REVIEW_DIGEST_MISMATCH')
    try:
        publication.run_identity(run,entry)
        publication.source_identity(f06,entry,root=source_root,head=head)
    except (F07Refused,lineage.Refused,ValueError):
        raise Refused('F08_F06_EXACT_SOURCE_OR_RUN_IDENTITY_INVALID') from None
    require(isinstance(release, dict) and release.get('tag_name') == tag and
            release.get('draft') is False and
            release.get('prerelease') is (entry['channel'] == 'beta') and
            isinstance(release.get('published_at'), str) and release['published_at'] and
            release.get('target_commitish') == entry['sourceMergedSha'] and
            (release.get('author') or {}).get('login') and
            isinstance(release.get('assets'), list) and release.get('body')==publication.release_notes(entry),
            'F08_PUBLIC_RELEASE_IDENTITY_INVALID')
    # gh release create --target creates the fork's lightweight Git tag.
    # target_commitish alone cannot detect a subsequently moved tag.
    require(isinstance(tag_ref, dict) and tag_ref.get('ref') == 'refs/tags/' + tag
            and isinstance(tag_ref.get('object'), dict) and
            tag_ref['object'].get('type') == 'commit' and
            tag_ref['object'].get('sha') == entry['sourceMergedSha'],
            'F08_GIT_TAG_REFERENCE_NOT_REVIEWED_SOURCE_COMMIT')
    # The retained report is also a published asset, bound by the independently
    # reviewed original signed report digest. Reconcile it with the separately
    # downloaded original Actions attestation, not merely F07's own assertion.
    try:
        retained = publication.read_signed_evidence(assets/'f06-signed-provenance.json',entry)
    except (F07Refused,ValueError,OSError):
        raise Refused('F08_RETAINED_SIGNED_EVIDENCE_DRIFT') from None
    require(retained==f06,'F08_ORIGINAL_F06_SIGNED_ATTESTATION_INVALID')
    f06_apks = f06.get('apks')
    require(isinstance(f06_apks, list) and 1 <= len(f06_apks) <= MAX_APKS and
            all(isinstance(x, dict) and isinstance(x.get('fileName'), str)
                for x in f06_apks) and
            len({x['fileName'] for x in f06_apks}) == len(f06_apks),
            'F08_ORIGINAL_F06_APK_INVENTORY_INVALID')
    f06_by_name = {x['fileName']: x for x in f06_apks}
    require(isinstance(compat, dict) and compat.get('schemaVersion') == 1 and
            isinstance(compat.get('apks'), list), 'F08_COMPATIBILITY_MANIFEST_INVALID')
    require(assets.is_dir() and not assets.is_symlink(), 'F08_ASSETS_DIRECTORY_INVALID')
    rows = provenance.get('apks')
    require(isinstance(rows, list) and 1 <= len(rows) <= MAX_APKS,
            'F08_ATTESTED_APK_COUNT_INVALID')
    names = [x.get('name') if isinstance(x, dict) else None for x in rows]
    require(all(isinstance(x, str) and APK.fullmatch(x) for x in names) and
            len(set(names)) == len(names), 'F08_APK_NAMES_DUPLICATE_OR_INVALID')
    require(set(f06_by_name) == set(names), 'F08_F06_F07_APK_SET_MISMATCH')
    expected = set(names) | {'manager-compatibility.json', 'f07-release-provenance.json', 'f06-signed-provenance.json'}
    actual_files = list(assets.iterdir())
    require(all(x.is_file() and not x.is_symlink() for x in actual_files) and
            {x.name for x in actual_files} == expected and
            len(actual_files) == len(expected), 'F08_ASSET_SET_INVALID')
    github_assets = release['assets']
    require(all(isinstance(x, dict) and isinstance(x.get('name'), str) and
                type(x.get('size')) is int and x['size'] > 0 for x in github_assets) and
            len(github_assets) == len(expected) and
            {x['name'] for x in github_assets} == expected,
            'F08_GITHUB_ASSET_SET_INVALID')
    gh_by_name = {x['name']: x for x in github_assets}
    require(all((assets / name).stat().st_size == gh_by_name[name]['size'] for name in expected),
            'F08_GITHUB_ASSET_SIZE_MISMATCH')
    # Every published APK and metadata asset must include an authoritative GitHub
    # sha256 digest, in addition to the original F06 independent provenance.
    # Absent digest must never produce a passing release-audit receipt.
    github_asset_digests = 0
    for asset_name in sorted(expected):
        stated = gh_by_name[asset_name].get('digest')
        require(stated is not None,
                'F08_GITHUB_ASSET_DIGEST_MISSING_'+asset_name)
        require(isinstance(stated, str) and
                re.fullmatch(r'sha256:[0-9a-f]{64}', stated) is not None,
                'F08_GITHUB_ASSET_DIGEST_FORMAT_INVALID_'+asset_name)
        require(stated == 'sha256:' + hash_file(assets / asset_name),
                'F08_GITHUB_ASSET_DIGEST_DRIFT_'+asset_name)
        github_asset_digests += 1
    compat_rows = compat['apks']
    require(len(compat_rows) == len(names) and all(isinstance(x, dict) for x in compat_rows),
            'F08_COMPATIBILITY_ROWS_INVALID')
    c_by_name = {x.get('fileName'): x for x in compat_rows}
    require(len(c_by_name) == len(names) and set(c_by_name) == set(names),
            'F08_COMPATIBILITY_APK_BINDING_INVALID')
    signer = entry['certificateSha256']
    try:
        aapt = str(sdk_tool('aapt', sdk))
        apksigner = str(sdk_tool('apksigner', sdk))
    except (SigningRefused, FileNotFoundError, OSError):
        raise Refused('F08_HOSTED_ANDROID_BUILD_TOOLS_MISSING') from None
    checked = []
    for row in sorted(rows, key=lambda x: x['name']):
        name = row['name']; file = assets / name
        pattern = APK.fullmatch(name)
        require(pattern is not None and type(row.get('sizeBytes')) is int and
                row['sizeBytes'] > 100_000 and
                row['sizeBytes'] == file.stat().st_size and
                isinstance(row.get('sha256'), str) and
                FINGERPRINT.fullmatch(row['sha256']) and
                hash_file(file) == row['sha256'], 'F08_APK_HASH_OR_SIZE_DRIFT')
        prior = f06_by_name[name]
        require(prior.get('fileName') == name and
                prior.get('sha256') == row['sha256'] and
                prior.get('sizeBytes') == row['sizeBytes'] and
                prior.get('signerCertificateSha256') == signer and
                prior.get('packageName') == PACKAGE and
                type(prior.get('versionCode')) is int and
                prior['versionCode'] == entry['versionCode'] and
                prior.get('versionName') == pattern.group(1) and
                prior.get('nativeAbis') == sorted(NATIVE_ABIS if pattern.group(3)=='universal' else {pattern.group(3)}),
                'F08_F06_SIGNED_APK_VS_PUBLISHED_HASH_DRIFT')
        candidate = c_by_name[name]
        require(set(candidate) == {'fileName', 'versionCode', 'abi', 'managerUapi',
                                   'minimumKernelSuVersion'} and
                candidate['fileName'] == name and
                type(candidate['versionCode']) is int and
                candidate['versionCode'] == entry['versionCode'] == int(pattern.group(2)) and
                candidate['abi'] == pattern.group(3) and
                type(candidate['managerUapi']) is int and
                candidate['managerUapi'] == entry['managerUapi'] and
                type(candidate['minimumKernelSuVersion']) is int and
                candidate['minimumKernelSuVersion'] == entry['minimumKernelSuVersion'],
                'F08_COMPATIBILITY_VALUES_NOT_REVIEWED')
        try:
            actual = apk_checker(file, aapt, apksigner, signer, PACKAGE)
        except (SigningRefused, OSError, ValueError):
            raise Refused('F08_APK_SIGNATURE_OR_METADATA_INVALID') from None
        require(actual.get('fileName') == name and
                actual.get('sha256') == row['sha256'] and
                actual.get('sizeBytes') == row['sizeBytes'] and
                actual.get('versionCode') == entry['versionCode'] and
                actual.get('versionName') == pattern.group(1) and
                actual.get('packageName') == PACKAGE and
                actual.get('signerCertificateSha256') == signer and
                actual.get('nativeAbis') == prior['nativeAbis'],
                'F08_APK_REVERIFICATION_MISMATCH')
        checked.append({'fileName': name, 'sha256': row['sha256'],
                        'versionCode': entry['versionCode'], 'abi': candidate['abi']})
    require(len({x['abi'] for x in checked}) == len(checked), 'F08_DUPLICATE_ABI_VARIANTS')
    # This report records reproducible facts only; no unsigned digest is ever
    # treated as a release signature or installed-device authorization.
    return {'schemaVersion': 1, 'repository': REPO,
            'status': 'f08-published-artifacts-verified', 'tag': tag,
            'f06RunId': entry['f06RunId'], 'f06RunAttempt':entry['f06RunAttempt'],
            'reservationId':entry['reservationId'],'sourceTree':entry['sourceTree'],
            'signedProvenanceSha256':entry['signedProvenanceSha256'], 'reviewDigest':lineage.digest(entry),
            'sourceMergedSha': entry['sourceMergedSha'],
            'forkMainAuditSha': head, 'certificateSha256': signer,
            'managerPackage': PACKAGE, 'apks': checked,
            'reviewedCompatibility': True, 'signedApksReverified': True,
            'publishedAssetIntegrity': True,
            'githubAssetDigestsChecked': github_asset_digests,
            'githubAssetDigestCoverageComplete': github_asset_digests == len(expected),
            'deviceQualified': False,
            'rootDaemonAuthorized': False, 'releaseBuildPerformed': False}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--tag', required=True)
    p.add_argument('--assets', type=Path, required=True)
    p.add_argument('--release-json', type=Path, required=True)
    p.add_argument('--tag-ref-json', type=Path, required=True)
    p.add_argument('--report', type=Path, required=True)
    p.add_argument('--sdk', type=Path, default=Path(os.getenv('ANDROID_HOME') or os.getenv('ANDROID_SDK_ROOT') or '/no-sdk'))
    args = p.parse_args(argv)
    try:
        head = exact_main()
        require(not args.report.exists() and not args.report.is_symlink(), 'F08_REPORT_ALREADY_EXISTS')
        require(args.assets.is_dir() and not args.assets.is_symlink(),
                'F08_ASSETS_DIRECTORY_INVALID')
        registry = read_json_file(ROOT/'config/fork-release-review.json')
        provenance = read_json_file(args.assets/'f07-release-provenance.json')
        compat = read_json_file(args.assets/'manager-compatibility.json')
        release = read_json_file(args.release_json)
        tag_ref = read_json_file(args.tag_ref_json)
        entry=reviewed_entry(registry,provenance['f06RunId'],args.tag,provenance['channel'])
        publication.review_continuity(ROOT,head,registry)
        run=publication.api(f'repos/{REPO}/actions/runs/{entry["f06RunId"]}')
        publication.run_identity(run,entry)
        # Exact attempt artifact metadata and downloaded bytes must match the
        # committed review. Expired or missing original evidence refuses rather
        # than claiming independent hosted qualification from release alone.
        publication.verify_f06_artifacts(entry)
        with tempfile.TemporaryDirectory(prefix='bakasu-f08-evidence-') as folder:
            evidence=Path(folder)/'evidence';evidence.mkdir()
            original_apks=Path(folder)/'apks';original_apks.mkdir()
            publication.download_f06_artifact(entry,'evidence',evidence)
            publication.download_f06_artifact(entry,'apk',original_apks)
            f06=publication.read_signed_evidence(evidence/'f06-signed-provenance.json',entry)
            require(lineage.read_json(evidence/'f06-promoted-source.json')==f06['source'],'F08_SOURCE_REPORT_DRIFT')
            report = check_release(args.tag,release,registry,provenance,run,compat,f06,
                                   args.assets,head=head,sdk=args.sdk,tag_ref=tag_ref)
            require({p.name for p in original_apks.iterdir()}=={x['fileName'] for x in report['apks']} and
                    all(hash_file(original_apks/x['fileName'])==x['sha256'] for x in report['apks']),
                    'F08_ORIGINAL_SIGNED_APK_ARCHIVE_DRIFT')
            report['originalProviderArchiveDigestsVerified']=True
        # Output is non-authorizing evidence. Exclusive creation prevents
        # a stale/foreign audit from being overwritten and misattributed.
        import stat
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        print('F08_PUBLISHED_RELEASE_AUDIT_PASS tag='+args.tag+
              ' signed_apks='+str(len(report['apks']))+
              ' not_device_qualified=1', flush=True)
        return 0
    except (Refused, F07Refused, SigningRefused, ValueError, OSError, KeyError,
            TypeError, subprocess.TimeoutExpired) as exc:
        print('F08_REFUSED '+str(exc), file=sys.stderr, flush=True)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
