# BakaSU F06 — persistent signer and source-pinned manager qualification

Repository `Mikeyphw/BakaSU`. This is **not** a signed release, updater publication, KernelSU daemon change, or on-device approval. F05 remains the source authority for upstream beta/stable event identity.

## Boundary

`.github/workflows/fork-f06-signed-manager.yml` is manual `workflow_dispatch` only, on the fork default branch **after PR review and merge**. It does not run with signing secrets on pull requests. It does not alter any fork branch, tag, GitHub release, or update feed. It integrates the event-pinned upstream SHA **only in a disposable hosted Actions checkout** and runs every existing fork source/regression gate again.

The isolated manager package ID is `com.mikeyphw.bakasu`, different from upstream `com.resukisu.resukisu`. Its signing identity must remain stable between versions. It must **not** be used to replace the daily root manager until daemon allowlist, install/update authorization, persisted key continuity, and device acceptance are qualified (F07/F09). Any candidate APK emitted by this workflow is explicitly diagnostic.

## One-time GitHub signer setup

Create a **persistent** Android keystore outside GitHub and keep an offline private backup. In repository Settings → Environments, create an environment named `fork-signing` and, ideally, require human reviewers. Configure five **environment secrets** (do not print or commit them):

- `FORK_SIGNER_KEYSTORE_B64` — base64 encoding of the exact keystore bytes, single line
- `FORK_SIGNER_STORE_PASSWORD` — keystore password
- `FORK_SIGNER_KEY_ALIAS` — keystore key alias, ASCII letter/digit/underscore/dot/hyphen
- `FORK_SIGNER_KEY_PASSWORD` — key password
- `FORK_SIGNER_CERT_SHA256` — expected SHA-256 digest of the signing certificate (64 hex characters)

Generate the digest from the signing certificate itself, not from the APK file or keystore file hash. Preserve and independently verify this identity across builds. The pipeline verifies every APK's signer against the explicitly supplied digest and requires APK v2 signing. No key is generated automatically and no short-lived PR key is accepted. Missing, mismatched or invalid secrets fail closed. Ephemeral Gradle properties and keystore material are removed from the hosted checkout; they are never uploaded as artifacts.

The digest is currently an **operator-provided trust anchor**. Before any future F07 release promotion, its fingerprint must be committed as a reviewed, public signer identity, corroborated against actual signed APKs and previous installed versions. Rotating this signing key can prevent Android updates; no automatic rotation is implemented.

## Operator flow

1. Confirm PR #1's current HEAD and required CI. Review/merge deliberately when ready; never auto-merge.
2. Configure the five environment secrets and `fork-signing` approval policy.
3. From Actions → *Fork F06 — Source-Pinned Signed Manager Qualification* → Run workflow (on `main`), enter `beta` or `stable`, the upstream event ID, exact upstream SHA, and the fork main HEAD SHA. F05 verifies the event again.
4. Inspect `f06-source-and-signer-evidence-*` and `f06-signed-manager-diagnostic-*`. The report proves only hosted source/signature/packaging checks. It does not claim release compatibility, device authorization or installation.
5. F07 will add source-pinned compatibility metadata and an explicitly approved fork-only GitHub release/update feed. It must not publish from a failed, untrusted or merely diagnostic F06 run.

F06 includes negative unit tests (wrong source, malformed signer digest, missing keystore, different package, missing v2 signature, multiple signers, mismatched version and unsafe workflow triggers) in the existing `.github/workflows/fork-manager-ci.yml` `test_*.py` discovery. The existing CodeQL, formatting, Rust/C, Gradle, and source-contract gates are preserved. Hosted Gradle and Android SDK acceptance are still pending until the workflow actually runs with valid secrets on the default branch.
