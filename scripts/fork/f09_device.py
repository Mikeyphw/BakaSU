#!/usr/bin/env python3
"""F09 non-mutating installed-manager evidence and independent review preparation.

Only explicit owner-selected ADB devices are read. No installation, permission
changes, root command, reboot, downgrade, manager registration, or flash.
Physical/manual evidence never becomes root authority or acceptance by itself.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import zipfile

import acceptance_evidence as ev
import event_journal as journal
import f07_release as publication
import release_lineage as lineage

STAGES = ('baseline', 'upgrade', 'reboot', 'rollback', 'recovery')
CASES = {
    'exact-version-reinstall': 'upgrade',
    'historical-version-discovery': 'upgrade',
    'wrong-module-zip-refused': 'upgrade',
    'changed-or-unsafe-archive-refused': 'upgrade',
    'module-state-preserved': 'recovery',
    'stable-beta-compatibility-gates': 'upgrade',
    'incompatible-and-wrong-signer-refused': 'upgrade',
    'authorized-manager-readonly-operation': 'upgrade',
    'authorization-after-reboot': 'reboot',
    'rollback-and-data-recovery': 'rollback',
    'authorization-after-recovery': 'recovery',
}
MAX_MANUAL = 16 * 1024 * 1024
SERIAL = re.compile(r'[A-Za-z0-9_.:\[\]-]{1,160}\Z')
PATH = re.compile(r'/data/app/(?:[A-Za-z0-9_=.~+-]+/)*com\.mikeyphw\.bakasu-[A-Za-z0-9_=.~+-]+/base\.apk\Z')
ABI = {'arm64-v8a', 'armeabi-v7a', 'armeabi', 'x86', 'x86_64', 'riscv64'}
UUID = re.compile(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z')


class Refused(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def device_hash(session, value):
    return hashlib.sha256((session+'\0'+value).encode()).hexdigest()


class Adb:
    def __init__(self, serial):
        require(isinstance(serial, str) and SERIAL.fullmatch(serial) and not serial.startswith('-'), 'DEVICE_EXPLICIT_SERIAL_REQUIRED')
        self.serial = serial

    def run(self, *args, timeout=35, optional=False):
        p = subprocess.run(['adb', '-s', self.serial, *args], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, check=False)
        if optional and p.returncode != 0:
            return None
        require(p.returncode == 0 and len(p.stdout) <= 65536, 'DEVICE_ADB_READ_FAILED')
        return p.stdout.decode('utf-8', errors='strict').strip()

    def path(self):
        value = self.run('shell', 'pm', 'path', '--user', '0', publication.PACKAGE)
        require(isinstance(value, str) and value.startswith('package:') and
                PATH.fullmatch(value.removeprefix('package:')) and '..' not in value.split('/'),
                'DEVICE_EXPECTED_SINGLE_STANDALONE_MANAGER_APK_REQUIRED')
        return value.removeprefix('package:')

    def size(self, path):
        require(PATH.fullmatch(path), 'DEVICE_UNSAFE_APK_PATH')
        out = self.run('shell', 'stat', '-c', '%s', path)
        require(re.fullmatch(r'[1-9][0-9]{0,9}', out or ''), 'DEVICE_APK_SIZE_INVALID')
        return int(out)

    def boot_id(self):
        value = self.run('shell', 'cat', '/proc/sys/kernel/random/boot_id', optional=True)
        return value if isinstance(value, str) and UUID.fullmatch(value) else None

    def pull(self, path, dest):
        require(PATH.fullmatch(path), 'DEVICE_UNSAFE_APK_PATH')
        self.run('pull', path, str(dest), timeout=240)


def apk_row(verified, filename):
    report = verified['report']
    matches = [row for row in report['apks'] if row['fileName'] == filename]
    require(len(matches) == 1 and isinstance(filename,str) and publication.APK.fullmatch(filename), 'DEVICE_EXPECTED_REVIEWED_APK_REQUIRED')
    return matches[0], report['githubAssets'][filename]


def collect(verified, filename, stage, session, adb, *, owner_device, now=None):
    require(owner_device is True and stage in STAGES and lineage.sha256(session), 'DEVICE_OWNER_STAGE_OR_SESSION_REQUIRED')
    row, asset = apk_row(verified, filename)
    require(adb.run('get-state') == 'device', 'DEVICE_NOT_AUTHORIZED_OR_CONNECTED')
    # These are negative emulator indicators only, not physical attestation.
    require(not adb.serial.startswith('emulator-') and all(adb.run('shell', 'getprop', p) not in ('1', 'true')
                for p in ('ro.kernel.qemu', 'ro.boot.qemu')), 'DEVICE_EMULATOR_REFUSED')
    raw_abis = adb.run('shell', 'getprop', 'ro.product.cpu.abilist')
    abis = raw_abis.split(',') if raw_abis else []
    require(abis and len(abis) == len(set(abis)) and set(abis) <= ABI and
            (row['abi'] in abis or row['abi'] == 'universal' and bool(set(abis) & {'arm64-v8a', 'armeabi-v7a', 'x86_64', 'riscv64'})),
            'DEVICE_APK_ABI_INCOMPATIBLE')
    sdk = adb.run('shell', 'getprop', 'ro.build.version.sdk')
    require(re.fullmatch(r'[1-9][0-9]{0,3}', sdk or ''), 'DEVICE_SDK_INVALID')
    before = adb.boot_id(); source = adb.path()
    require(adb.size(source) == asset['size'] and 0 < asset['size'] <= 1073741824, 'DEVICE_APK_SIZE_DRIFT')
    with tempfile.TemporaryDirectory(prefix='bakasu-f09-installed-') as folder:
        installed = Path(folder)/'installed.apk'
        adb.pull(source, installed)
        require(installed.is_file() and not installed.is_symlink() and installed.stat().st_size == asset['size'] and
                publication.digest(installed) == row['sha256'], 'DEVICE_INSTALLED_APK_BYTES_NOT_REVIEWED')
    require(adb.path() == source and adb.size(source) == asset['size'] and adb.boot_id() == before and
            adb.run('get-state') == 'device', 'DEVICE_CHANGED_DURING_CAPTURE')
    # Verify the package manager's currently referenced bytes again after pull;
    # do not merely rely on the source path remaining the same.
    remote = adb.run('shell', 'sha256sum', source)
    require(remote.split() == [row['sha256'], source], 'DEVICE_LIVE_APK_HASH_DRIFT')
    report = verified['report']
    return {'schemaVersion': 1, 'repository': ev.REPO, 'stage': stage, 'session': session,
            'observedAt': journal.timestamp(now or datetime.now(timezone.utc)),
            'deviceId': device_hash(session, adb.serial), 'bootId': device_hash(session, before) if before else None,
            'sdk': int(sdk), 'abis': abis, 'tag': report['tag'], 'releaseId': verified['releaseId'],
            'auditReference': verified['reference'], 'auditArtifactSha256': verified['artifactSha256'],
            'sourceTree': report['sourceTree'], 'reservationId': report['reservationId'],
            'certificateSha256': report['certificateSha256'], 'packageName': publication.PACKAGE,
            'apk': row, 'sizeBytes': asset['size'], 'installedBytesVerified': True,
            'ownerDeclaredPhysicalDevice': True, 'deviceQualified': False, 'rootDaemonAuthorized': False}


def validate_capture(record, verified, stage, session):
    require(isinstance(record, dict) and record.get('schemaVersion') == 1 and record.get('repository') == ev.REPO and
            record.get('stage') == stage and record.get('session') == session and lineage.sha256(record.get('deviceId')) and
            (record.get('bootId') is None or lineage.sha256(record['bootId'])) and journal.integer(record.get('sdk'), 1, 9999) and
            isinstance(record.get('abis'), list) and record['abis'] and all(isinstance(x, str) and x in ABI for x in record['abis']) and
            len(record['abis']) == len(set(record['abis'])), 'DEVICE_CAPTURE_SCHEMA_INVALID')
    require(isinstance(record.get('apk'), dict), 'DEVICE_CAPTURE_APK_MISSING')
    row, asset = apk_row(verified, record['apk'].get('fileName'))
    report = verified['report']
    require(record['apk'] == row and record.get('sizeBytes') == asset['size'] and
            (row['abi'] in record['abis'] or row['abi'] == 'universal' and bool(set(record['abis']) & {'arm64-v8a','armeabi-v7a','x86_64','riscv64'})) and
            record.get('packageName') == publication.PACKAGE and record.get('tag') == report['tag'] and
            record.get('releaseId') == verified['releaseId'] and record.get('auditReference') == verified['reference'] and
            record.get('auditArtifactSha256') == verified['artifactSha256'] and
            all(record.get(k) == report[k] for k in ('sourceTree','reservationId','certificateSha256')) and
            record.get('installedBytesVerified') is True and record.get('ownerDeclaredPhysicalDevice') is True and
            record.get('deviceQualified') is False and record.get('rootDaemonAuthorized') is False, 'DEVICE_CAPTURE_RELEASE_OR_SCOPE_DRIFT')
    journal.utc(record['observedAt'])
    return record


def evidence_file(folder, row):
    require(isinstance(row, dict) and set(row) == {'file','sha256'} and isinstance(row['file'], str) and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', row['file']) and '..' not in row['file'] and
            lineage.sha256(row['sha256']), 'DEVICE_MANUAL_EVIDENCE_REFERENCE_INVALID')
    path = folder/row['file']
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= MAX_MANUAL and
            publication.digest(path) == row['sha256'], 'DEVICE_MANUAL_EVIDENCE_BYTES_DRIFT')
    return row['sha256']


def review_session(captures, manual, verified_by_tag, folder):
    """Validate receipt relationships and raw evidence inventory, not truth of manual claims."""
    require(isinstance(captures, list) and len(captures) == len(STAGES), 'DEVICE_FIVE_STAGE_CAPTURES_REQUIRED')
    require(isinstance(manual, dict) and set(manual) == {'schemaVersion','session','cases'} and manual['schemaVersion'] == 1 and
            lineage.sha256(manual['session']) and isinstance(manual['cases'], list), 'DEVICE_MANUAL_REVIEW_SCHEMA_INVALID')
    session = manual['session']
    rows = []
    for stage, record in zip(STAGES, captures):
        require(isinstance(record, dict) and record.get('tag') in verified_by_tag, 'DEVICE_UNVERIFIED_STAGE_RELEASE')
        rows.append(validate_capture(record, verified_by_tag[record['tag']], stage, session))
    baseline, upgrade, reboot, rollback, recovery = rows
    times = [journal.utc(row['observedAt']) for row in rows]
    require(all(a < b for a,b in zip(times,times[1:])) and len({r['deviceId'] for r in rows}) == 1 and
            len({r['certificateSha256'] for r in rows}) == 1 and len({(r['sdk'],tuple(r['abis'])) for r in rows}) == 1,
            'DEVICE_SESSION_TIME_IDENTITY_OR_SIGNER_DRIFT')
    require(baseline['apk']['versionCode'] < upgrade['apk']['versionCode'] and
            baseline['tag'] == rollback['tag'] and baseline['apk'] == rollback['apk'] and
            upgrade['tag'] == reboot['tag'] == recovery['tag'] and upgrade['apk'] == reboot['apk'] == recovery['apk'] and
            baseline['reservationId'] == rollback['reservationId'] and upgrade['reservationId'] == reboot['reservationId'] == recovery['reservationId'],
            'DEVICE_UPGRADE_ROLLBACK_RECOVERY_LINEAGE_DRIFT')
    reboot_verified = bool(upgrade['bootId'] and reboot['bootId'] and upgrade['bootId'] != reboot['bootId'])
    results, evidence_seen = {}, set()
    for case in manual['cases']:
        require(isinstance(case, dict) and set(case) == {'id','stage','result','observation','evidence'} and
                case['id'] in CASES and case['id'] not in results and case['stage'] == CASES[case['id']] and
                case['result'] in ('PASS','FAIL','PENDING') and isinstance(case['observation'], str) and len(case['observation']) <= 600 and
                isinstance(case['evidence'], list) and len(case['evidence']) <= 4, 'DEVICE_MANUAL_CASE_INVALID')
        require(case['result'] == 'PENDING' or (case['observation'].strip() and case['evidence']), 'DEVICE_MANUAL_OBSERVATION_REQUIRED')
        for ref in case['evidence']:
            digest = evidence_file(folder, ref)
            require(digest not in evidence_seen, 'DEVICE_MANUAL_EVIDENCE_REUSED')
            evidence_seen.add(digest)
        results[case['id']] = case['result']
    require(set(results) == set(CASES), 'DEVICE_MANUAL_CASE_ROSTER_INCOMPLETE')
    failures = sorted(k for k,v in results.items() if v == 'FAIL')
    pending = sorted(k for k,v in results.items() if v == 'PENDING')
    return {'schemaVersion': 1, 'repository': ev.REPO, 'session': session,
            'status': 'DEVICE_EVIDENCE_REVIEW_REQUIRED' if not failures and not pending and reboot_verified else 'DEVICE_EVIDENCE_INCOMPLETE_OR_FAILED',
            'captureDigests': [lineage.digest(r) for r in rows], 'manualManifestDigest': lineage.digest(manual),
            'deviceId': upgrade['deviceId'], 'candidateTag': upgrade['tag'], 'baselineTag': baseline['tag'],
            'candidateTree': upgrade['sourceTree'], 'candidateApk': upgrade['apk'], 'signer': upgrade['certificateSha256'],
            'bootIdChanged': reboot_verified, 'manualResultsReportedByOwner': results, 'failedCases': failures, 'pendingCases': pending,
            'independentPhysicalReviewRequired': True, 'deviceQualified': False, 'rootDaemonAuthorized': False}


def signer_review(root, head, certificate):
    """Review the existing kernel trust path, using public DER only, never register it."""
    require(certificate.is_file() and not certificate.is_symlink() and 256 <= certificate.stat().st_size <= 1024,
            'DEVICE_PUBLIC_DER_CERTIFICATE_REQUIRED')
    der = certificate.read_bytes()
    # Parse and re-encode the exact public X.509 DER. Trailing bytes and PEM are refused.
    result = subprocess.run(['openssl','x509','-inform','DER','-outform','DER'], input=der,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    require(result.returncode == 0 and result.stdout == der, 'DEVICE_INVALID_OR_NONCANONICAL_PUBLIC_DER_CERTIFICATE')
    digest = hashlib.sha256(der).hexdigest(); policy = lineage.policy_at(root, head)
    require(policy['certificateSha256'] == digest, 'DEVICE_CERTIFICATE_NOT_REVIEWED')
    lineage.signer_continuity(root, head, digest)
    paths = ('kernel/manager/manager_sign.h', 'kernel/manager/apk_sign.c', 'kernel/feature/dynamic_manager.c',
             'kernel/supercall/dispatch.c', 'kernel/Kbuild', 'userspace/ksud/src/android/dynamic_manager.rs')
    blobs = {path: lineage.git(root, 'show', head+':'+path) for path in paths}
    sign = blobs[paths[0]].decode(); verifier = blobs[paths[1]].decode(); dispatcher = blobs[paths[3]].decode()
    size = re.search(r'(?m)^#define EXPECTED_SIZE_BAKASU (0x[0-9a-fA-F]+|[0-9]+)$', sign)
    h = re.search(r'(?m)^#define EXPECTED_HASH_BAKASU "([a-f0-9]{64})"$', sign)
    require(size and h and '#define CERT_MAX_LENGTH 1024' in verifier and
            'certificate_size == sign_key.size && strcmp(sign_key.sha256, hash_str) == 0' in verifier and
            '{ EXPECTED_SIZE_BAKASU, EXPECTED_HASH_BAKASU }' in verifier and
            re.search(r'\.cmd\s*=\s*KSU_IOCTL_DYNAMIC_MANAGER,\s*\.name\s*=\s*"SET_DYNAMIC_MANAGER",\s*\.handler\s*=\s*do_dynamic_manager,\s*\.perm_check\s*=\s*only_root',dispatcher),
            'DEVICE_KERNEL_TRUST_SOURCE_CHANGED_REVIEW_REQUIRED')
    return {'schemaVersion': 1, 'repository': ev.REPO, 'reviewedSource': head, 'managerPackage': publication.PACKAGE,
            'certificateSha256': digest, 'certificateDerBytes': len(der),
            'defaultBakaSUStaticKeyMatches': len(der) == int(size.group(1),0) and digest == h.group(1),
            'dynamicManagerRootPermissionSourcePresent': True, 'sourceHashes': {k:hashlib.sha256(v).hexdigest() for k,v in blobs.items()},
            'installedKernelIdentityRequired': True, 'manualAuthorizedKernelReviewRequired': True,
            'deviceQualified': False, 'rootDaemonAuthorized': False}


def read_capture(path):
    return lineage.read_json(path, ev.MAX_REPORT)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    template = sub.add_parser('template'); template.add_argument('--output', type=Path, required=True)
    signer = sub.add_parser('signer-review'); signer.add_argument('--certificate-der', type=Path, required=True); signer.add_argument('--output', type=Path, required=True)
    capture = sub.add_parser('capture'); capture.add_argument('--reference', type=Path, required=True); capture.add_argument('--apk', required=True); capture.add_argument('--serial', required=True); capture.add_argument('--session', required=True); capture.add_argument('--stage', choices=STAGES, required=True); capture.add_argument('--owner-device', action='store_true'); capture.add_argument('--output', type=Path, required=True)
    review = sub.add_parser('review'); review.add_argument('--folder', type=Path, required=True); review.add_argument('--output', type=Path, required=True)
    a = p.parse_args(argv)
    try:
        if a.command == 'template':
            value = {'schemaVersion': 1, 'session': secrets.token_hex(32), 'cases': [dict(id=k, stage=v, result='PENDING', observation='', evidence=[]) for k,v in CASES.items()]}
        else:
            head = ev.exact_main(); registry = ev.committed_registry(ev.ROOT, head)
            if a.command == 'signer-review':
                value = signer_review(ev.ROOT, head, a.certificate_der)
            elif a.command == 'capture':
                require(a.owner_device, 'DEVICE_EXPLICIT_OWNER_CONSENT_REQUIRED')
                verified = ev.fetch_live_audit(read_capture(a.reference), registry, head=head)
                value = collect(verified, a.apk, a.stage, a.session, Adb(a.serial), owner_device=a.owner_device)
            else:
                folder = ev.private_directory(a.folder)
                rows = [read_capture(folder/(stage+'.json')) for stage in STAGES]
                verified = {}
                for row in rows:
                    tag = row['tag']; ref = row['auditReference']
                    if tag not in verified:
                        verified[tag] = ev.fetch_live_audit(ref, registry, head=head)
                    else:
                        require(ref == verified[tag]['reference'], 'DEVICE_AUDIT_REFERENCE_CHANGED')
                value = review_session(rows, read_capture(folder/'manual.json'), verified, folder)
            require(ev.exact_main() == head, 'DEVICE_MAIN_DRIFT_DURING_REVIEW')
        checksum = ev.write_private(a.output, value)
        print('BK_GAP05_DEVICE_EVIDENCE_WRITTEN sha256='+checksum+' independent_review_required=1')
        return 1 if value.get('status') == 'DEVICE_EVIDENCE_INCOMPLETE_OR_FAILED' else 0
    except (ValueError, RuntimeError, OSError, KeyError, TypeError, AttributeError, subprocess.SubprocessError, zipfile.BadZipFile) as exc:
        # Refusal codes only: avoid printing paths, device serial, provider body or credentials.
        code = str(exc) if isinstance(exc,(Refused,ev.Refused,lineage.Refused,publication.Refused,journal.JournalError)) and re.fullmatch(r'[A-Za-z0-9_]+',str(exc)) else type(exc).__name__
        print('BK_GAP05_DEVICE_REFUSED '+code, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
