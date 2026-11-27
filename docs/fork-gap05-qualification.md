# GAP-05 — evidence reconciliation and final acceptance preparation

- P01: independent F08 workflow attempt, artifact ID/digest, release ID,
  tag and complete asset identity, with committed source history and reread.
- P02: actual public DER signer trust-path review and read-only installed APK
  capture using explicit owner-selected ADB, exact release bytes and ABI.
- P03: five-stage device evidence and eleven manual case checks, with
  fail-closed continuity and mandatory independent physical review.
- P04: durable original F06/F08 archive retention and offline replay with
  exact source, provider snapshot, raw archive, APK and manifest checks.
- P05: complete ten-milestone R9 factual audit, cross-channel version floor,
  durable journal identity, real hosted/diagnostic/scheduled observations.

Local tests use disposable Git repositories, synthetic provider ZIPs and
APK metadata, a disposable public DER certificate and controlled ADB fixture.
No genuine signed APK, release signing environment, physical hardware,
privileged authorization or actual release publication is tested locally.
No changes to kernel trust checks, installed device, secrets or owner journal.
The real first/second signed releases and actual device evidence remain
external acceptance gates, not an implementation denominator adjustment.

### Termux compatibility (GAP-05-HF01)

Evidence output remains exclusive and atomic if Python does not expose `os.link`: on Android API 30+ / Linux with filesystem support, `renameat2(RENAME_NOREPLACE)` publishes the fully synced temporary file. Existing files and symlinks cannot be replaced. If no safe exclusive publication primitive is available, refuse the operation and remove the temporary file; do not create a partially written public receipt. Regression qualification exercises the original suite with `os.link` absent and concurrent writers on a disposable filesystem. Real Android execution remains separately qualified.
