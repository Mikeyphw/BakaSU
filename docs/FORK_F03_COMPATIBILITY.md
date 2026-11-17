# BakaSU fork — F03 compatibility gate and fork-only update discovery

Source-pinned to PR #1 head `41f9e43cc4f06d4807ac46ac3c27e3185143ceae`.

## What this overlay delivers

- Carries forward the F01/F02 baseline (no source reset). Manager Reinstall is untouched.
- Both stable and beta update discovery now point only at `Mikeyphw/BakaSU`.
- Beta candidates are taken from *published prereleases* of this fork, not unsigned upstream workflow artifacts.
- A published beta requires `manager-compatibility.json` attached to the **same release** to prove candidate manager UAPI and minimum KernelSU version.
- The metadata entry must match the exact APK fileName, versionCode and ABI. Duplicates, invalid and missing values fail closed.
- Unverified/incompatible beta updates show a non-clickable explanation, not an Update action.
- Before starting a compatible beta download, BakaSU re-reads the kernel status and blocks if compatibility has changed.
- English and pt-BR strings provided.

## Release manifest (for F04–F07)

Attach a release asset named `manager-compatibility.json` with the following format, generated from the *candidate APK build* after successful CI (never guessed from the installed manager):

```json
{
  "schemaVersion": 1,
  "apks": [
    {
      "fileName": "BakaSU_<version>_<versionCode>-arm64-v8a-release.apk",
      "versionCode": 12345,
      "abi": "arm64-v8a",
      "managerUapi": 1,
      "minimumKernelSuVersion": 12345
    }
  ]
}
```

Example values are placeholders, **not** validated compatibility requirements. F04–F07 must generate those fields from the actual source/build and ensure the release APK is signed with an authorized manager identity. An exact UAPI match and minimum KernelSU version prove only those checked conditions, not universal functional compatibility.

## Limitations / next gates

- The fork currently has no signed stable/beta releases. Existing in-app update channels therefore yield no eligible published fork APK.
- This is an F03 manager-side source and UI gate; actual candidate metadata and signed release automation come in F04–F07.
- Stable and beta release channels now both require candidate-specific compatibility metadata. Unknown or incompatible candidates are shown as blocked; neither channel bypasses the final kernel-state check.
- No APK signing, publication, installation, kernel modifications, root/device changes, or local Gradle.
- GitHub Actions must pass compilation, lint, source contracts and build gates before merging/deploying.
