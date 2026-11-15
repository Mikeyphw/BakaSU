# BakaSU fork — F01/HF01 + F02 consolidated overlay

Source-pinned overlay for PR #1 (`feature/f01-fork-manager-baseline-20261115`).

## Included

- F01/HF01: fix the GitHub Actions whitespace check by comparing the PR's base/head source commits with full Git history.
- F02: add an exact-version **Reinstall** button beside the Update / Uninstall actions.
- A module is eligible only after its `updateJson` has been fetched and offers the **installed** versionCode as an HTTPS ZIP URL. No install is triggered automatically.
- The ordinary Update button continues to depend on a versionCode greater than the installed one.
- Registry-linked ZIPs retain the registry size/SHA-256 verification and stale-selection protections. For author-provided legacy ZIPs, a clear *unverified source* confirmation is displayed. This does **not** prove the ZIP matches the installed module ID.
- The existing module flash screen performs installation only after confirmation, download, and existing checks.
- English and Brazilian Portuguese labels/confirmations; other locales fall back to English.

## Not included yet

- F03 beta manager/kernel compatibility checks.
- F04–F07 upstream build tracking, signed fork APK releases, fork-only in-app update endpoints.
- Signed release APK or device qualification.

**Important:** The existing manager APK update checker still targets upstream; do not install this baseline APK as a daily driver until the later fork-only update and authorization/signature phases are complete.

## Validation and release policy

- `inspect` is read-only; `apply` changes exactly the 8 pinned files and adds this document and 1 regression source-contract test.
- Full Kotlin compilation and Android build are **only** run in GitHub Actions. This overlay has not passed hosted CI until the PR checks succeed.
- No kernel code, `ksud`, signing secret, root operations, device installation, release publishing, auto-merge, or forced pushes.
- Fail closed on mismatched branch, local/remote HEAD, dirty worktree, source Git blobs, missing anchors, test failure or Git whitespace errors.
