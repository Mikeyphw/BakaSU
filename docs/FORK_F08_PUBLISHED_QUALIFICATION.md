# F08 — Independent, read-only signed release audit

This is an additional qualification layer for `Mikeyphw/BakaSU`, **not** a
replacement for the F06 signing gate, F07 controlled publisher, or F09 device
acceptance. It never creates a tag, alters a release, signs an APK, installs
anything, or authorizes the privileged manager with the root daemon.

## Security authority and workflow

`.github/workflows/fork-f08-release-qualification.yml` is manual-only and
requires the reviewed F07 tag of an **already published** release. It runs on
fork `main` with only `contents: read` and `actions: read`, downloads solely
that fork release, reads the GitHub release, the original F06 signed-evidence artifact and
workflow-run metadata, and does not persist checkout credentials. It cannot run as an
unreviewed pull-request job with release privileges.

The independent verifier `scripts/fork/f08_qualification.py` requires:

- an exact single committed review entry with source SHA, fixed signer certificate,
  F06 run ID, channel, version code, manager UAPI and minimum KernelSU version;
- a successful manual F06 run from the fork's own main with the exact workflow
  path, source SHA, and run attempt, plus a publicly published F07 tag;
- an F07 source merge commit that remains an ancestor of the audited fork main;
- the actual fork Git tag ref must still point at that reviewed source commit, not
  merely carry a matching `target_commitish` field in release metadata;
- require GitHub-provided `sha256:` digests for every APK and JSON metadata
  asset; absent, malformed or mismatched digests refuse release qualification;
- exact GitHub asset inventory, byte lengths, separately attested APK SHA-256s
  **cross-checked against the original F06 signed APK attestation**,
  version code and compatible ABI, with no extra or duplicate APKs;
- **real Android `apksigner` verification** of each APK's v2 signature,
  certificate SHA-256 and fork package ID `com.mikeyphw.bakasu`, plus actual
  APK package/version metadata from Android build tools;
- the existing F03 `manager-compatibility.json` format with exact APK
  filename/version/ABI matches and approved manager UAPI/minimum KernelSU data.

Malformed, missing, conflicting, truncated, oversized or unreviewed evidence
fails closed. F08 writes only a small diagnostic JSON audit receipt to the
runner temporary directory, then retains that report as a GitHub Actions
artifact for review. It does not upload private keys or APKs to a second
location. **A passing F08 audit is hosted artifact verification, not device
or privileged-daemon qualification.**

## Operating sequence

1. Review and merge F06/F07/F08 to main; complete the persistent signing setup.
2. Build a real F06 candidate and commit its integrated source to fork main;
   manually review the source/signature/compatibility record, then explicitly
   publish with the protected F07 workflow. A review registry entry must not
   be inferred from the local device or generated automatically.
3. Manually run *Fork F08 — Read-Only Published Manager Qualification* on main,
   supplying the exact published `f07-v*` tag. Review the signed-audit artifact
   and run logs on the exact workflow HEAD.
4. Only F09 may pursue physical Android installation, manager allowlist
   authorization, persistent signer continuity and update/reinstall behavior.

The F07 registry is **not** required to remain empty forever: once the
operator adds source-reviewed entries, the existing F07 regression suite must
still exercise those current entries instead of imposing an obsolete empty-only
test. The reviewed registry is currently empty, so no F07 release can yet be
approved or audited.
