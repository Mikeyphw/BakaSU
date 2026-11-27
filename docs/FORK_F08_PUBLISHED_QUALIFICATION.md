# F08 — independent published release verification

Manual-only on fork main, `contents: read` and `actions: read`. Never signs,
publishes, installs, or authorizes a daemon. Run only after an explicitly
approved real F07 release. Supply the exact reviewed `f07-v` tag.

The verifier downloads public release assets and actual tag/ref metadata,
validates the committed append-only F07 registry, confirms source ancestry,
exact promoted tree and historical F06 signer/reservation policy, and confirms
the original successful manual F06 run and exact attempt. It downloads both
original F06 ZIPs by reviewed immutable provider ID and verifies raw provider
archive hashes before bounded safe extraction. The retained original signed
report in the published release must match the independently reviewed raw bytes
and original provider report. Every original signed APK hash must equal the
published APK hash; the independently downloaded GitHub release assets must all
have matching GitHub SHA-256 digests and sizes, with no extra/missing files.

It then independently verifies every published APK using Android SDK tools:
exact package, signer certificate, v2 signature, version and native ABI inventory,
plus candidate-specific compatibility UAPI/minimum KernelSU manifest and exact
reviewed release/tag identity. The result is hosted artifact qualification,
**not** device acceptance or privileged root authorization. No keys are used.

Run the audit before the original provider artifact retention expires and keep
the actual report plus both original archives in private durable storage. The
released `f06-signed-provenance.json` preserves the original reviewed report, but
expired/missing provider archives still block a new full hosted F08 acceptance;
retained proof alone is not a substitute for independently fetched provider
identity. No automatic bypass is implemented. F09 must test the actual signed
manager on a physical device separately. No reviewed release is currently
configured or claimed accepted.
