# BakaSU fork — F01 baseline

Upstream: https://github.com/Baka-SU/BakaSU
Target: https://github.com/Mikeyphw/BakaSU

## Scope

- F01 establishes a dedicated source-compatibility contract and Android-manager-only CI smoke build.
- This is intentionally NOT a release pipeline, module-reinstall implementation, compatibility gate, or auto-upstream publisher yet.
- The imported manager remains upstream-identical during F01. Upstream APK update endpoints are **not** switched yet: do not install the baseline debug APK as your daily manager.
- No local Gradle, kernel/ksud modification, root writes, APK installation, auto-merge, or release publication.

## Follow-up work

- F02 add a separately labeled module Reinstall action, preserving registry verification.
- F03 publish and enforce candidate manager/kernel compatibility requirements.
- F04/F05 detect upstream successful beta workflow runs and stable releases, source-pin and build fork artifacts.
- F06/F07 publish signed fork-only APKs and point both app update channels exclusively to fork release metadata.
- F08/F09 qualify tests, signature/manager authorization and physical-device install.

## Build gate

`.github/workflows/fork-manager-ci.yml` runs the source-seam contract, negative tests, and `:app:assembleDebug` using GitHub Actions. Artifacts are diagnostic only, not installable release deliverables.

The fork bootstrap creates a draft pull request and does **not** merge it automatically. If Actions is initially disabled on the fork, enable it under Settings → Actions before running the workflow.

## 2026-11-18 post-refork current-state addendum

This F01 document is historical baseline documentation. The fork is now at
`feature/f01-fork-manager-baseline-20261115` commit
`eb68d9d2d5ed02a11d3c9ece76f847b9ca5d0cf1` on recreated GitHub
repository ID `1462243855`. F02 secure Reinstall, F03 stable compatibility,
manager APK integrity and F08 digest audit were introduced after F01.
The original `onUpdateModule(uri)` integration seam was replaced by
`onUpdateModule(uri, installedModule?, expectedSha256, expectedSize)`,
which routes a verified reinstall to `Route.Flash.moduleReinstall(...)`.
Source-contract tests must enforce the current safe route and flash-time
module identity check, not obsolete F01 callback text.

Current CI: source-contract failed on its obsolete token; manager lint
failed on formatting. This repair keeps hosted Gradle formatting/build
as the authoritative gate; no Gradle is run in Termux. CI results and
physical-device qualification must be verified after native delivery.

Devtool runner policy: the same native overlay adds .devtool.toml with runner = python for source-contract tests. Since the native CLI resolves the initial runner before overlay extraction, a launcher-level explicit runner is still needed for first full apply. No Gradle is run in Termux.
