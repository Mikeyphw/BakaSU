# F09 — physical-device and kernel trust review

The collector is deliberately read-only. It does not install or downgrade an
APK, register a manager, grant permissions, execute root commands, flash a
module or reboot a device. Its result is never an acceptance or root grant.
Use an explicitly owner-approved spare physical device, a verified recovery
backup, working ADB and two **already published, independently F08-qualified**
manager releases signed by the same committed signer. A first release alone
cannot establish the upgrade/rollback sequence. Do not substitute a debug APK.

## Prerequisites

- A clean full-history local checkout of canonical fork main, authenticated
  read-only `gh`, ADB, Python 3 and OpenSSL. No local Gradle is necessary.
- The actual installed kernel/daemon identity, capability/UAPI and supported
  ABI, plus independently reviewed root trust mechanism. The existing kernel
  recognizes known certificate hashes; its dynamic-manager ioctl is root-only.
  The fork package name and an APK signature by themselves do not confer root.
- Review the public DER certificate against the committed F06 policy using
  `signer-review`; it reports whether the built-in static BakaSU key matches.
  A mismatch is an unresolved device trust gate, **not** an instruction to
  bypass checks. Any change to trusted keys needs separate source review,
  explicit owner authorization and rollback/recovery planning.
- Prepare an owner-private evidence directory (`mkdir -m 700 ...`), not a
  shared download folder. Store no keystore, passwords, tokens or raw serials
  in evidence. Independently redact manual logs and screenshots.

## Read-only collection

From the repository, replace placeholders using actual provider records:

```sh
python3 -B scripts/fork/f09_device.py template --output "$evidence/manual.json"
python3 -B scripts/fork/f09_device.py signer-review --certificate-der "$public_der" --output "$evidence/signer.json"
python3 -B scripts/fork/f09_device.py capture --reference "$reference" --apk "$apk_filename" --serial "$serial" --session "$session" --stage baseline --owner-device --output "$evidence/baseline.json"
```

The reference JSON has `tag`, `runId`, `runAttempt`, `artifactId` only, from
an actual successful F08 run and its matching artifact. The session comes
from `manual.json`. Capture uses the selected device's standalone installed
`com.mikeyphw.bakasu` base APK, verifies its exact bytes, ABI and live release
identity, and checks for device/boot/path changes during capture. A split APK,
wrong bytes, incompatible ABI, emulator indicator, stale provider artifact or
uncertain release identity refuses. Absence of emulator indicators is not
proof of physical hardware. Device/boot tokens are session-hashed; do not
share the raw serial.

Capture each stage as a separate file: `baseline.json`, `upgrade.json`,
`reboot.json`, `rollback.json`, `recovery.json`. The baseline and rollback
must match, and upgrade/reboot/recovery must match a newer version; a real
boot ID change between upgrade and reboot is required. All five must be
on the same device with the same reviewed signer. Owner performs each
approved operation separately, following the device's documented recovery
procedure. Stop on failure; do not perform destructive rollback merely to
complete a checklist.

Complete the eleven explicit manual cases in the template with `PASS`, `FAIL`
or `PENDING`; for non-pending cases supply observation plus unique redacted
file references `{ "file": "case.txt", "sha256": "..." }`. Include actual
root-denial/authorized read-only behavior, negative compatibility and
reinstall tests, state preservation and recovery. The review verifies receipt
relationships and manual evidence digests; it cannot independently establish
the truth of owner assertions or the running kernel identity. Never label
untested cases PASS. Run:

```sh
python3 -B scripts/fork/f09_device.py review --folder "$evidence" --output "$evidence/review.json"
```

A complete report is `DEVICE_EVIDENCE_REVIEW_REQUIRED`; incomplete/failed
cases or missing reboot proof remain incomplete. Only independent review of
actual device evidence and kernel trust can close F09. Source fixtures do not
satisfy it. There is no automated grant or root-authorization success flag.
