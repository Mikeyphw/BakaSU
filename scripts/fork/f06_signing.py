#!/usr/bin/env python3
"""F06 hosted-only persistent-key signature qualification. No publication or install.

The caller must be on fork main, with a reviewed GAP-03 journal reservation.
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

import release_lineage as lineage
from f05_dispatch import Client, DispatchError
from promotion_plan import published_version_floor

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / 'config/fork-signing-contract.json'
FORK = 'Mikeyphw/BakaSU'
SHA = re.compile(r'^[a-f0-9]{40}$')
CERT = re.compile(r'^[a-f0-9]{64}$')
ALIAS = re.compile(r'^[a-zA-Z0-9._-]{1,64}$')
APK_NAME = re.compile(r'BakaSU_([A-Za-z0-9._+-]{1,128})_([1-9][0-9]{0,9})-(arm64-v8a|armeabi-v7a|x86_64|riscv64|universal)-release\.apk\Z')
NATIVE_ABIS = frozenset(('arm64-v8a','armeabi-v7a','x86_64','riscv64'))
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
    return lineage.signing_policy(lineage.read_json(path))


def fingerprint(value: str) -> str:
    need(isinstance(value, str), 'F06_CERT_FINGERPRINT_NOT_TEXT')
    result = value.lower().replace(':', '')
    need(CERT.fullmatch(result) is not None, 'F06_CERT_SHA256_NOT_64_HEX')
    return result


def source(report: Path, *, expected_fork: str = '', channel: str = '', policy=None) -> dict:
    record = lineage.read_json(report)
    need(set(record) == {'schemaVersion','mode','status','forkSha','reservation','certificateSha256','runId','runAttempt'} and
         record['schemaVersion'] == 2 and record['mode'] == 'F06-promoted-reservation' and
         record['status'] == 'source-promoted-reviewed' and SHA.fullmatch(str(record['forkSha'])) and
         lineage.positive(record['runId']) and lineage.positive(record['runAttempt']), 'F06_PROMOTED_SOURCE_REPORT_INVALID')
    policy = contract() if policy is None else lineage.signing_policy(policy)
    reservation = lineage.validate_reservation(record['reservation'])
    need(lineage.reviewed_reservation(policy,reservation['reservationId'],reservation['versionCode']) == reservation and
         record['certificateSha256'] == policy['certificateSha256'], 'F06_REVIEWED_SOURCE_OR_SIGNER_DRIFT')
    need((not expected_fork or record['forkSha'] == expected_fork) and
         (not channel or reservation['channel'] == channel), 'F06_SOURCE_CHANNEL_OR_FORK_MISMATCH')
    return record


def github_context() -> None:
    need(os.getenv('GITHUB_ACTIONS') == 'true' and
         os.getenv('GITHUB_REPOSITORY') == FORK and
         os.getenv('GITHUB_REF') == 'refs/heads/main' and
         os.getenv('GITHUB_EVENT_NAME') == 'workflow_dispatch',
         'F06_GITHUB_HOSTED_FORK_MAIN_ONLY')


def checkout_identity(record: dict, checkout: Path, *, prepared=False) -> None:
    row = record['reservation']
    for spec,key in (('HEAD','sourceCommit'),('HEAD^{tree}','sourceTree')):
        need(lineage.git(checkout,'rev-parse','--verify',spec).decode().strip() == row[key],
             'F06_PROMOTED_CHECKOUT_IDENTITY_MISMATCH_'+key)
    changes = lineage.git(checkout,'status','--porcelain=v1','-z','--untracked-files=no')
    need(changes in ((b'',b' M manager/gradle.properties\0') if prepared else (b'',)), 'F06_PROMOTED_CHECKOUT_DIRTY')


def invocation(record, env):
    need(env.get('GITHUB_SHA') == record['forkSha'] and
         env.get('GITHUB_RUN_ID') == str(record['runId']) and
         env.get('GITHUB_RUN_ATTEMPT') == str(record['runAttempt']), 'F06_ACTIONS_IDENTITY_DRIFT')


def write_exclusive(output, data):
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def stage(reservation_id, version, fork, checkout, output, env, *, root=ROOT, client=None):
    github_context()
    need(env.get('GITHUB_SHA') == fork and SHA.fullmatch(fork) and
         lineage.git(root,'rev-parse','HEAD').decode().strip() == fork and
         not lineage.git(root,'status','--porcelain=v1','--untracked-files=all'), 'F06_WORKFLOW_SOURCE_DRIFT')
    policy = lineage.policy_at(root,fork)
    row = lineage.reviewed_reservation(policy,reservation_id,version)
    lineage.committed_source(root,row,fork)
    lineage.signer_continuity(root,fork,policy['certificateSha256'])
    client = Client(env.get('GITHUB_TOKEN','')) if client is None else client
    remote = client.request('/git/ref/heads/main')
    need(remote.get('ref') == 'refs/heads/main' and remote.get('object',{}).get('sha') == fork,'F06_REMOTE_MAIN_DRIFT')
    lineage.verify_diagnostic(row,client.request)
    need(version > published_version_floor(client),'F06_RESERVED_VERSION_ALREADY_PUBLISHED_OR_STALE')
    need(not checkout.exists() and not checkout.is_symlink() and not output.exists() and not output.is_symlink(),
         'F06_STAGING_PATH_EXISTS')
    record = {'schemaVersion':2,'mode':'F06-promoted-reservation','status':'source-promoted-reviewed',
              'forkSha':fork,'reservation':row,'certificateSha256':policy['certificateSha256'],
              'runId':int(env.get('GITHUB_RUN_ID','0')),'runAttempt':int(env.get('GITHUB_RUN_ATTEMPT','0'))}
    need(lineage.positive(record['runId']) and lineage.positive(record['runAttempt']), 'F06_ACTIONS_RUN_INVALID')
    lineage.git(root,'worktree','add','--detach',str(checkout),row['sourceCommit'])
    checkout_identity(record,checkout)
    write_exclusive(output, (json.dumps(record,sort_keys=True,indent=2)+'\n').encode())
    print('F06_COMMITTED_SOURCE_VERIFIED reservation='+reservation_id+' version='+str(version),flush=True)
    return record


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


def verify_keystore(path: Path, alias: str, storepass: str, expected: str) -> None:
    # Password travels in the child environment, never argv, report or logs.
    env = dict(os.environ,F06_KEYTOOL_STOREPASS=storepass)
    p = subprocess.run(['keytool','-exportcert','-keystore',str(path),'-alias',alias,
                        '-storepass:env','F06_KEYTOOL_STOREPASS'],env=env,capture_output=True,timeout=45)
    need(p.returncode == 0 and 0 < len(p.stdout) <= 65536 and
         hashlib.sha256(p.stdout).hexdigest() == expected, 'F06_KEYSTORE_CERTIFICATE_MISMATCH')


def prepare(report_path: Path, manager: Path, scratch: Path, env: dict[str, str]) -> dict:
    github_context()
    record = source(report_path, expected_fork=env.get('GITHUB_SHA', ''))
    invocation(record,env)
    checkout_identity(record,manager.parent)
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
    need(expected == record['certificateSha256'], 'F06_SIGNER_SECRET_NOT_REVIEWED')
    orig = gradle.read_bytes()
    original_mode = stat.S_IMODE(gradle.stat().st_mode)
    need(original_mode in (0o600,0o644), 'F06_GRADLE_PROPERTIES_MODE_REFUSED')
    need(0 < len(orig) <= 256 * 1024, 'F06_GRADLE_PROPERTIES_SIZE_REFUSED')
    need(not any(re.search(rb'(?m)^\s*' + k.encode() + rb'\s*=', orig) for k in KEYS),
         'F06_EXISTING_SIGNING_PROPERTY_CONFLICT')
    # O_EXCL protects journal and key; never replace an existing signer.
    try:
        for path, data in ((snapshot, (f'{original_mode:04o}\n').encode()+orig), (key_file, raw)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        verify_keystore(key_file,alias,storepass,expected)
        data = ('\n' if orig and not orig.endswith(b'\n') else '') + '\n'.join(
            k + '=' + java_property(v) for k, v in (
                ('KEYSTORE_FILE', str(key_file)), ('KEYSTORE_PASSWORD', storepass),
                ('KEY_ALIAS', alias), ('KEY_PASSWORD', keypass))) + '\n'
        gradle.chmod(0o600)
        with gradle.open('ab') as stream:
            stream.write(data.encode('ascii'))
            stream.flush()
            os.fsync(stream.fileno())
        print('F06_PERSISTENT_SIGNER_PREPARED source=' + record['reservation']['sourceCommit'][:12] +
              ' expected_cert=' + expected[:12] + ' secrets_not_logged=1', flush=True)
        return {'expectedCertificateSha256': expected, 'source': record}
    except BaseException:
        # Do not leave a half-prepared credential or stale private journal.
        # Existing Gradle properties were checked and snapshotted before writing.
        try:
            if snapshot.exists():
                gradle.write_bytes(orig)
                gradle.chmod(original_mode)
                snapshot.unlink()
        finally:
            if key_file.exists():
                key_file.unlink()
        raise


def cleanup(manager: Path, scratch: Path) -> None:
    gradle = manager / 'gradle.properties'
    key_file = scratch / 'f06-manager-key.jks'
    snapshot = scratch / 'f06-gradle.original'
    if not snapshot.exists() and not snapshot.is_symlink() and not key_file.exists() and not key_file.is_symlink():
        return
    try:
        regular(gradle)
        if snapshot.exists() or snapshot.is_symlink():
            regular(snapshot)
            mode,sep,data = snapshot.read_bytes().partition(b'\n')
            need(sep and mode in (b'0600',b'0644') and 0 < len(data) <= 256 * 1024, 'F06_SNAPSHOT_CORRUPTED')
            gradle.write_bytes(data)
            gradle.chmod(int(mode,8))
            snapshot.unlink()
    finally:
        if key_file.exists() or key_file.is_symlink():
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
    name = APK_NAME.fullmatch(apk.name)
    need(name is not None and apk.stat().st_size > 100_000,
         'F06_APK_MISSING_OR_INVALID')
    signed = command(apksigner, 'verify', '--verbose', '--print-certs', str(apk))
    signatures = SIGNER_LINE.findall(signed)
    need(len(signatures) == 1 and fingerprint(signatures[0]) == expected_cert,
         'F06_SIGNER_CERTIFICATE_MISMATCH')
    need(re.search(r'(?m)^Verified using v2 scheme \(APK Signature Scheme v2\): true\s*$', signed),
         'F06_APK_V2_SIGNATURE_MISSING')
    need('Signer #2 certificate SHA-256 digest:' not in signed, 'F06_MULTIPLE_SIGNERS_REFUSED')
    badging = command(aapt, 'dump', 'badging', str(apk))
    package = PKG_LINE.search(badging)
    need(package is not None and package.group(1) == expected_package and
         0 < int(package.group(2)) <= 2_100_000_000 and len(package.group(3)) <= 128,
         'F06_MANAGER_PACKAGE_OR_VERSION_MISMATCH')
    need(name.group(1)==package.group(3) and int(name.group(2))==int(package.group(2)), 'F06_APK_FILENAME_VERSION_DRIFT')
    lines = re.findall(r'(?m)^native-code:([^\n]+)$',badging)
    need(len(lines)==1, 'F06_APK_NATIVE_ABI_MISSING')
    abis = re.findall(r"'([^']+)'",lines[0])
    need(len(abis)==len(set(abis)) and set(abis)==(NATIVE_ABIS if name.group(3)=='universal' else {name.group(3)}), 'F06_APK_NATIVE_ABI_MISMATCH')
    with apk.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'fileName': apk.name, 'sha256': digest, 'sizeBytes': apk.stat().st_size,
            'packageName': package.group(1), 'versionCode': int(package.group(2)),
            'versionName': package.group(3), 'nativeAbis':sorted(abis), 'signerCertificateSha256': expected_cert}


def verify(report_path: Path, apk_dir: Path, output: Path, *, expected_cert: str,
           sdk: Path, expected_fork: str = '', checkout: Path = ROOT) -> dict:
    rules = contract()
    record = source(report_path, expected_fork=expected_fork)
    cert = fingerprint(expected_cert)
    github_context()
    invocation(record,os.environ)
    need(cert == record['certificateSha256'], 'F06_SIGNER_SECRET_NOT_REVIEWED')
    checkout_identity(record,checkout,prepared=True)
    need(apk_dir.is_dir() and not apk_dir.is_symlink(), 'F06_APK_DIR_INVALID')
    apks = sorted(apk_dir.glob('*.apk'))
    need(1 <= len(apks) <= 12 and not output.exists() and not output.is_symlink(),
         'F06_APK_COUNT_OR_REPORT_CONFLICT')
    aapt = str(sdk_tool('aapt', sdk))
    apksigner = str(sdk_tool('apksigner', sdk))
    results = [apk_metadata(x, aapt, apksigner, cert, rules['managerPackage']) for x in apks]
    codes = {x['versionCode'] for x in results}
    versions = {x['versionName'] for x in results}
    need(codes == {record['reservation']['versionCode']} and len(versions) == 1, 'F06_RESERVED_APK_VERSION_MISMATCH')
    audit = {'schemaVersion': 2, 'mode': 'F06-signed-artifact-not-a-release',
             'repository': FORK, 'status': 'signed-verified',
             'source': record,
             'reservationId':record['reservation']['reservationId'],
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
    stage_parser = sub.add_parser('stage')
    stage_parser.add_argument('--reservation-id',required=True)
    stage_parser.add_argument('--version-code',type=int,required=True)
    stage_parser.add_argument('--fork-sha',required=True)
    stage_parser.add_argument('--checkout',type=Path,required=True)
    stage_parser.add_argument('--output',type=Path,required=True)
    a = sub.add_parser('prepare')
    a.add_argument('--source', type=Path, required=True)
    a.add_argument('--manager', type=Path, default=ROOT/'manager')
    a.add_argument('--scratch', type=Path, required=True)
    b = sub.add_parser('verify')
    b.add_argument('--source', type=Path, required=True)
    b.add_argument('--apk-dir', type=Path, required=True)
    b.add_argument('--output', type=Path, required=True)
    b.add_argument('--sdk', type=Path, default=Path(os.getenv('ANDROID_HOME') or os.getenv('ANDROID_SDK_ROOT') or '/__no_sdk__'))
    b.add_argument('--fork-sha', required=True)
    b.add_argument('--checkout',type=Path,required=True)
    c = sub.add_parser('cleanup')
    c.add_argument('--manager', type=Path, default=ROOT/'manager')
    c.add_argument('--scratch', type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.mode == 'stage':
            stage(args.reservation_id,args.version_code,args.fork_sha,args.checkout,args.output,os.environ)
        elif args.mode == 'prepare':
            prepare(args.source,args.manager,args.scratch,os.environ)
        elif args.mode == 'verify':
            verify(args.source,args.apk_dir,args.output,
                   expected_cert=os.environ.get('FORK_SIGNER_CERT_SHA256',''),
                   sdk=args.sdk,expected_fork=args.fork_sha,checkout=args.checkout)
        else:
            cleanup(args.manager,args.scratch)
        return 0
    except (Refused,ValueError,KeyError,OSError,TypeError,DispatchError,subprocess.SubprocessError) as exc:
        print('F06_REFUSED '+str(exc),file=sys.stderr,flush=True)
        return 2

if __name__ == '__main__':
    sys.exit(main())
