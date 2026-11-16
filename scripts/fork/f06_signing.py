#!/usr/bin/env python3
"""F06 hosted-only persistent-key signature qualification. No publication or install.

The caller must be on fork main, with exact F05 source integration evidence.
Never prints credentials, decodes them into reports, or generates signing keys.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / 'config/fork-signing-contract.json'
FORK = 'Mikeyphw/BakaSU'
SHA = re.compile(r'^[a-f0-9]{40}$')
CERT = re.compile(r'^[a-f0-9]{64}$')
ALIAS = re.compile(r'^[a-zA-Z0-9._-]{1,64}$')
APK_NAME = re.compile(r'^[A-Za-z0-9._+-]+\.apk$')
PKG_LINE = re.compile(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", re.M)
SIGNER_LINE = re.compile(r'(?m)^Signer #1 certificate SHA-256 digest: ([a-fA-F0-9:]+)\s*$')
KEYS = ('KEYSTORE_FILE', 'KEYSTORE_PASSWORD', 'KEY_ALIAS', 'KEY_PASSWORD')
MAX_KEY_BYTES = 1024 * 1024


class Refused(RuntimeError):
    pass


def need(ok: object, problem: str) -> None:
    if not ok:
        raise Refused(problem)


def contract(path: Path = CONTRACT_PATH) -> dict:
    raw = json.loads(path.read_text(encoding='utf-8'))
    need(isinstance(raw, dict) and raw.get('schemaVersion') == 1 and
         raw.get('repository') == FORK and raw.get('branch') == 'main' and
         raw.get('managerPackage') == 'com.mikeyphw.bakasu' and
         raw.get('buildMode') == 'manual-source-pinned-signing-diagnostic' and
         raw.get('releasePublication') is False and raw.get('deviceInstallation') is False and
         raw.get('requireV2Signature') is True and
         raw.get('requireExpectedSignerFingerprint') is True and
         raw.get('compatibilityManifestPublished') is False,
         'F06_SIGNING_CONTRACT_INVALID')
    return raw


def fingerprint(value: str) -> str:
    need(isinstance(value, str), 'F06_CERT_FINGERPRINT_NOT_TEXT')
    result = value.lower().replace(':', '')
    need(CERT.fullmatch(result) is not None, 'F06_CERT_SHA256_NOT_64_HEX')
    return result


def source(report: Path, *, expected_fork: str = '', channel: str = '') -> dict:
    record = json.loads(report.read_text(encoding='utf-8'))
    need(isinstance(record, dict) and record.get('schemaVersion') == 1 and
         record.get('status') in ('source-integrated', 'debug-build-validated') and
         record.get('mode') == 'F05-unsigned-diagnostic-only', 'F06_F05_SOURCE_REPORT_INVALID')
    need(all(SHA.fullmatch(str(record.get(k, ''))) for k in
             ('forkSha', 'upstreamSha', 'mergedSha', 'mergedTreeSha')), 'F06_SOURCE_SHA_INVALID')
    need(record.get('channel') in ('beta', 'stable') and
         (not channel or record.get('channel') == channel) and
         (not expected_fork or record.get('forkSha') == expected_fork),
         'F06_SOURCE_CHANNEL_OR_FORK_MISMATCH')
    need(type(record.get('upstreamEventId')) is int and record['upstreamEventId'] > 0,
         'F06_UPSTREAM_EVENT_ID_MISSING')
    return record


def github_context() -> None:
    need(os.getenv('GITHUB_ACTIONS') == 'true' and
         os.getenv('GITHUB_REPOSITORY') == FORK and
         os.getenv('GITHUB_REF') == 'refs/heads/main',
         'F06_GITHUB_HOSTED_FORK_MAIN_ONLY')


def checkout_identity(record: dict) -> None:
    # Require the checkout that actually passed F05's source/event integration.
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS='1')
    for spec, key in (('HEAD', 'mergedSha'), ('HEAD^{tree}', 'mergedTreeSha')):
        p = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', spec],
                           capture_output=True, text=True, env=env, timeout=25,
                           check=False)
        need(p.returncode == 0 and p.stdout.strip() == record[key],
             'F06_INTEGRATED_CHECKOUT_IDENTITY_MISMATCH_'+key)


def safe_secret(env: dict[str, str], key: str) -> str:
    value = env.get(key, '')
    need(isinstance(value, str) and 8 <= len(value) <= 256 and
         all(32 <= ord(c) <= 126 for c in value), 'F06_SECRET_UNSET_OR_INVALID_'+key)
    return value


def java_property(value: str) -> str:
    # Properties parsing is not shell parsing. Escape all separators and spaces.
    return ''.join('\\' + c if c in ('\\', ' ', '=', ':', '#', '!') else c for c in value)


def regular(path: Path, *, must_exist: bool = True) -> None:
    if not path.exists() and not path.is_symlink() and not must_exist:
        return
    need(not path.is_symlink() and path.is_file() and stat.S_ISREG(path.stat().st_mode),
         'F06_UNSAFE_FILE_'+path.name)


def prepare(report_path: Path, manager: Path, scratch: Path, env: dict[str, str]) -> dict:
    github_context()
    contract()
    record = source(report_path, expected_fork=env.get('GITHUB_SHA', ''))
    need(env.get('GITHUB_SHA') == record['forkSha'], 'F06_ACTIONS_SHA_DRIFT')
    checkout_identity(record)
    need(manager.resolve().is_dir() and scratch.resolve().is_dir(), 'F06_REQUIRED_DIRECTORY_MISSING')
    gradle = manager / 'gradle.properties'
    regular(gradle)
    need(not scratch.is_symlink() and not manager.is_symlink(), 'F06_DIRECTORY_SYMLINK')
    key_file = scratch / 'f06-manager-key.jks'
    snapshot = scratch / 'f06-gradle.original'
    need(not key_file.exists() and not key_file.is_symlink() and
         not snapshot.exists() and not snapshot.is_symlink(), 'F06_SIGNING_STATE_ALREADY_EXISTS')
    encoded = env.get('FORK_SIGNER_KEYSTORE_B64', '')
    need(isinstance(encoded, str) and 100 <= len(encoded) <= MAX_KEY_BYTES * 2,
         'F06_KEYSTORE_SECRET_UNSET_OR_INVALID')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise Refused('F06_KEYSTORE_NOT_VALID_BASE64') from None
    need(100 <= len(raw) <= MAX_KEY_BYTES, 'F06_KEYSTORE_SIZE_INVALID')
    storepass = safe_secret(env, 'FORK_SIGNER_STORE_PASSWORD')
    keypass = safe_secret(env, 'FORK_SIGNER_KEY_PASSWORD')
    alias = env.get('FORK_SIGNER_KEY_ALIAS', '')
    need(ALIAS.fullmatch(alias) is not None, 'F06_KEY_ALIAS_INVALID')
    expected = fingerprint(env.get('FORK_SIGNER_CERT_SHA256', ''))
    orig = gradle.read_bytes()
    need(0 < len(orig) <= 256 * 1024, 'F06_GRADLE_PROPERTIES_SIZE_REFUSED')
    need(not any(re.search(rb'(?m)^\s*' + k.encode() + rb'\s*=', orig) for k in KEYS),
         'F06_EXISTING_SIGNING_PROPERTY_CONFLICT')
    # O_EXCL protects journal and key; never replace an existing signer.
    try:
        for path, data in ((snapshot, orig), (key_file, raw)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        data = ('\n' if orig and not orig.endswith(b'\n') else '') + '\n'.join(
            k + '=' + java_property(v) for k, v in (
                ('KEYSTORE_FILE', str(key_file)), ('KEYSTORE_PASSWORD', storepass),
                ('KEY_ALIAS', alias), ('KEY_PASSWORD', keypass))) + '\n'
        with gradle.open('ab') as stream:
            stream.write(data.encode('ascii'))
            stream.flush()
            os.fsync(stream.fileno())
        print('F06_PERSISTENT_SIGNER_PREPARED source=' + record['mergedSha'][:12] +
              ' expected_cert=' + expected[:12] + ' secrets_not_logged=1', flush=True)
        return {'expectedCertificateSha256': expected, 'source': record}
    except BaseException:
        # Do not leave a half-prepared credential or stale private journal.
        # Existing Gradle properties were checked and snapshotted before writing.
        if snapshot.exists():
            gradle.write_bytes(orig)
        if key_file.exists():
            key_file.unlink()
        if snapshot.exists():
            snapshot.unlink()
        raise


def cleanup(manager: Path, scratch: Path) -> None:
    gradle = manager / 'gradle.properties'
    key_file = scratch / 'f06-manager-key.jks'
    snapshot = scratch / 'f06-gradle.original'
    regular(gradle)
    if snapshot.exists():
        regular(snapshot)
        data = snapshot.read_bytes()
        need(len(data) <= 256 * 1024 and len(data) > 0, 'F06_SNAPSHOT_CORRUPTED')
        gradle.write_bytes(data)
        snapshot.unlink()
    if key_file.exists():
        regular(key_file)
        key_file.unlink()
    print('F06_SIGNER_CLEANED_NO_KEY_MATERIAL_IN_ARTIFACTS', flush=True)


def sdk_tool(name: str, sdk_root: Path) -> Path:
    need(name in ('aapt', 'apksigner'), 'F06_TOOL_INVALID')
    root = sdk_root.resolve(strict=True)
    versions = sorted((p for p in (root / 'build-tools').iterdir()
                       if p.is_dir() and not p.is_symlink()), reverse=True)
    for p in versions:
        candidate = p / name
        if candidate.is_file() and not candidate.is_symlink() and os.access(candidate, os.X_OK):
            return candidate
    raise Refused('F06_ANDROID_SDK_TOOL_MISSING_'+name)


def command(*args: str) -> str:
    p = subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, timeout=80, check=False)
    need(p.returncode == 0, 'F06_TOOL_FAILED_'+Path(args[0]).name)
    return p.stdout


def apk_metadata(apk: Path, aapt: str, apksigner: str, expected_cert: str, expected_package: str) -> dict:
    regular(apk)
    need(APK_NAME.fullmatch(apk.name) is not None and apk.stat().st_size > 100_000,
         'F06_APK_MISSING_OR_INVALID')
    signed = command(apksigner, 'verify', '--verbose', '--print-certs', str(apk))
    signatures = SIGNER_LINE.findall(signed)
    need(len(signatures) == 1 and fingerprint(signatures[0]) == expected_cert,
         'F06_SIGNER_CERTIFICATE_MISMATCH')
    need(re.search(r'(?m)^Verified using v2 scheme \(APK Signature Scheme v2\): true\s*$', signed),
         'F06_APK_V2_SIGNATURE_MISSING')
    need('Signer #2 certificate SHA-256 digest:' not in signed, 'F06_MULTIPLE_SIGNERS_REFUSED')
    package = PKG_LINE.search(command(aapt, 'dump', 'badging', str(apk)))
    need(package is not None and package.group(1) == expected_package and
         0 < int(package.group(2)) <= 2_100_000_000 and len(package.group(3)) <= 128,
         'F06_MANAGER_PACKAGE_OR_VERSION_MISMATCH')
    with apk.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'fileName': apk.name, 'sha256': digest, 'sizeBytes': apk.stat().st_size,
            'packageName': package.group(1), 'versionCode': int(package.group(2)),
            'versionName': package.group(3), 'signerCertificateSha256': expected_cert}


def verify(report_path: Path, apk_dir: Path, output: Path, *, expected_cert: str,
           sdk: Path, expected_fork: str = '') -> dict:
    rules = contract()
    record = source(report_path, expected_fork=expected_fork)
    cert = fingerprint(expected_cert)
    checkout_identity(record)
    need(apk_dir.is_dir() and not apk_dir.is_symlink(), 'F06_APK_DIR_INVALID')
    apks = sorted(apk_dir.glob('*.apk'))
    need(1 <= len(apks) <= 12 and not output.exists() and not output.is_symlink(),
         'F06_APK_COUNT_OR_REPORT_CONFLICT')
    aapt = str(sdk_tool('aapt', sdk))
    apksigner = str(sdk_tool('apksigner', sdk))
    results = [apk_metadata(x, aapt, apksigner, cert, rules['managerPackage']) for x in apks]
    codes = {x['versionCode'] for x in results}
    versions = {x['versionName'] for x in results}
    need(len(codes) == len(versions) == 1, 'F06_INCONSISTENT_APK_VERSIONS')
    audit = {'schemaVersion': 1, 'mode': 'F06-signed-artifact-not-a-release',
             'repository': FORK, 'status': 'signed-verified',
             'source': {k: record[k] for k in ('forkSha', 'upstreamSha', 'mergedSha',
                                              'mergedTreeSha', 'channel', 'upstreamEventId')},
             'certificateSha256': cert, 'apks': results,
             'releaseQualified': False, 'deviceQualified': False,
             'compatibilityQualified': False}
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(audit, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    print('F06_SIGNED_APK_VERIFIED count=' + str(len(apks)) +
          ' signer=' + cert[:12] + ' not_released=1 not_device_qualified=1', flush=True)
    return audit


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='mode', required=True)
    a = sub.add_parser('prepare')
    a.add_argument('--source', type=Path, required=True)
    a.add_argument('--manager', type=Path, default=ROOT/'manager')
    a.add_argument('--scratch', type=Path, required=True)
    b = sub.add_parser('verify')
    b.add_argument('--source', type=Path, required=True)
    b.add_argument('--apk-dir', type=Path, required=True)
    b.add_argument('--output', type=Path, required=True)
    b.add_argument('--sdk', type=Path, default=Path(os.getenv('ANDROID_HOME') or os.getenv('ANDROID_SDK_ROOT') or '/__no_sdk__'))
    b.add_argument('--fork-sha', default='')
    c = sub.add_parser('cleanup')
    c.add_argument('--manager', type=Path, default=ROOT/'manager')
    c.add_argument('--scratch', type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.mode == 'prepare':
            prepare(args.source,args.manager,args.scratch,os.environ)
        elif args.mode == 'verify':
            verify(args.source,args.apk_dir,args.output,
                   expected_cert=os.environ.get('FORK_SIGNER_CERT_SHA256',''),
                   sdk=args.sdk,expected_fork=args.fork_sha)
        else:
            cleanup(args.manager,args.scratch)
        return 0
    except (Refused,ValueError,KeyError,OSError,subprocess.TimeoutExpired) as exc:
        print('F06_REFUSED '+str(exc),file=sys.stderr,flush=True)
        return 2

if __name__ == '__main__':
    sys.exit(main())
