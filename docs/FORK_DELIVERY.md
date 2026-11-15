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
