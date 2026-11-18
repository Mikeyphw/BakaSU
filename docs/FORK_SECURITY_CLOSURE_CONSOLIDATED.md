# BakaSU consolidated source-security closure candidate

This overlay is *source-level remediation*, not an Android release or F09 device
qualification. Native Devtool alone applies/commits the exact file inventory.

## F02 reinstall

Module ZIP is copied into app-private temporary storage. The flash stage rejects
untrusted ZIP entries, wrong module IDs, mismatched registry size/SHA-256 when
supplied, changed installed module identity and stale module state; all errors
refuse the privileged flash. Legacy author-hosted ZIPs remain explicitly warned
as unverified and cannot bypass the module-ID/ZIP structure checks. The disabled
state is rechecked and restored when possible; failures remain visible.

When updateJson supplies the installed ZIP, exact-version reinstall remains
independent of Update. If it instead supplies only a newer ZIP, the fallback is
separately labelled and requires explicit confirmation. Historical version
archives outside updateJson still require further registry/author integration.

## F03 / F07 APK checks

Both stable and beta require APK-specific compatibility requirements and check
live kernel UAPI/version/authorization before downloading. Published fork release
APK assets require GitHub's SHA-256 digest and size. The downloaded APK is
rehashed and its actual Android package, version and certificate continuity are
checked. The click-through installer is a nonexported internal gate which
rechecks live kernel compatibility and verifies an app-private APK copy, then
uses the normal system installer with explicit user action. Missing proof blocks.

Implementation-specific kernel capability metadata, independent published APK
proof beyond GitHub metadata, historical beta/stable version-code allocation,
and F09 real-device authorization remain necessary before release acceptance.

## F08

Requires GitHub sha256 digests for every release asset and verifies the actual
reviewed tag-ref, with adversarial Python tests. Missing digests fail closed. Independent F08 remains read-only and manual on
published fork main, and requires real release artifacts for final acceptance.

## F04-F07/F10 automation

Existing upstream discovery/F05 diagnostic pipeline remains in place. F06 signer,
F07 publisher and F08 read-only verifier must not be falsely described as fully
automatic. No automatic merge, signing, release, device operation or GitHub
publication is authorized by this overlay. Durable recovery and safe automatic
source-to-release lifecycle need separate reviewed implementation/CI evidence.

## Evidence and limitations

Preflight pins the existing fork feature-branch HEAD/tree/blob identities. The
Devtool runtime is dynamically resolved and verified against canonical current
main on each execution, without a hardcoded Devtool source commit. Only native
Devtool performs source validation, atomic changes, persistent sessions and PR.
The local Python F08 regressions do NOT prove Android compilation, device safety,
real release signing, hosted F08 or F09 acceptance. The PR must remain draft
until all required hosted checks and external qualification are complete.
