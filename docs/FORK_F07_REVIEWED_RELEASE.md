# F07 — reviewed, source-pinned BakaSU releases

F07 is an **opt-in** publisher, never a release-triggered workflow. It is not
activated on PRs or on F05 diagnostic events. It cannot publish until F06 is
merged and a manually approved F06 signed workflow has actually succeeded on
`main` using a persistent key. F06 currently remains diagnostic-only by itself.

## Review and trust requirements

1. Merge a reviewed F06/F07 PR to the fork `main` **manually** after its required
   CI passes. Provision the persistent `fork-signing` environment and its five
   signer secrets, retaining an offline keystore backup. Do not replace your
   daily root manager with these builds.
2. Run the manual F06 workflow with an exact qualified upstream event and fork
   source. Confirm the F06 source and signed APK provenance, package
   `com.mikeyphw.bakasu`, certificate fingerprint, and an integrated source
   commit actually present in committed `main` history. A disposable F05 merge
   that was never committed to `main` is **not** eligible for F07.
3. In a **separate reviewed commit**, add exactly one entry to
   `config/fork-release-review.json` recording that F06 run ID, channel,
   `f07-v...` tag, exact fork and merged source commits, version code,
   certificate SHA-256, `managerUapi` and `minimumKernelSuVersion`.
   These UAPI/kernel values must come from reviewed candidate source and test
   evidence, **not from the installed device**, guesswork, or arbitrary user
   input. The registry intentionally starts with an empty list: **no releases
   are eligible yet**.
4. Create a protected GitHub Actions environment named `fork-release` with
   required human reviewers. Only then manually dispatch **Fork F07 — Reviewed
   Signed Manager Release** on fork `main` with the exact registry run, tag and
   channel. No tag push, scheduled run, default merge or automatic promotion is
   enabled for F07.

## Prepublication checks

F07 independently checks original F06 run identity, success, source repo/branch,
exact signed provenance, committed integrated ancestor/tree, all APK sizes and
SHA-256s, Android APK v2 signatures and fixed fork certificate, exact manager
package/version/ABI, one matching reviewed registry record, monotonic version
codes against published fork APK assets, and asset consistency. It generates
`manager-compatibility.json` in the F03 updater schema from the reviewed
candidate-specific compatibility entry. Missing/unreviewed source/API proof
fails closed.

It uses a `f07-v...` tag prefix specifically to avoid triggering the inherited
`release.yml` `v*` automatic build/publisher. It creates a **draft release**,
checks every uploaded asset by downloading it and comparing SHA-256, and only
then publishes it. If interrupted after draft creation, the workflow refuses
another publish attempt for the same tag and leaves the draft for deliberate
operator recovery; it never overwrites assets or a different release.

GitHub environment reviewers and signing key configuration are external
operator steps. No keys, tokens or APKs are committed. F07 tests source and
signature requirements; it does not qualify root daemon package allowlists,
physical-device installation, long-term key custody, or release distribution
on untested devices. Those require separate F08/F09 evidence.
