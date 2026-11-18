# BakaSU F02 — current reinstall and ZIP identity contract

Source-pinned overlay for PR #1 (`feature/f01-fork-manager-baseline-20261115`).

## Included

- The current manager-only CI preserves meaningful source, formatter and regression tests, including PR base/head whitespace checks.
- F02: add an exact-version **Reinstall** button beside the Update / Uninstall actions.
- A module is eligible when its `updateJson` exposes an HTTPS ZIP for the exact installed version, or a newer version as a distinctly labelled latest-ZIP alternative. Neither is flashed automatically; historical release catalog search is still pending.
- The ordinary Update button continues to depend on a versionCode greater than the installed one.
- Registry-linked ZIPs retain the registry size/SHA-256 and stale-selection protections. A separate flash-time ZIP inspection now compares `module.prop` ID with the installed module, rejects unsafe ZIP entries and rechecks the installed state. Legacy author ZIPs remain explicitly unverified for origin/integrity.
- The existing module flash screen performs installation only after confirmation, download, and existing checks.
- English and Brazilian Portuguese labels/confirmations; other locales fall back to English.

## Not included yet

- Historical ZIP release catalog discovery and any author-specific ZIP archives not described in `updateJson`.
- Independent device-based module reinstall acceptance.
- Complete F04–F10 automatic signing/release/recovery and physical device authorization acceptance.

**Important:** The update checker now points to fork releases only, but signed releases, persistent signer continuity and root-manager authorization are not yet qualified; do not install the unqualified debug APK as a daily driver.

## Validation and release policy

- Native Devtool builds and validates exact-source overlay payloads, applies changes atomically and provides durable delivery sessions. Do not use obsolete historical F01/HFxx file counts as current acceptance gates.
- Full Kotlin compilation and Android build are **only** run in GitHub Actions. This overlay has not passed hosted CI until the PR checks succeed.
- No kernel code, `ksud`, signing secret, root operations, device installation, release publishing, auto-merge, or forced pushes.
- Fail closed on mismatched branch, local/remote HEAD, dirty worktree, source Git blobs, missing anchors, test failure or Git whitespace errors.
