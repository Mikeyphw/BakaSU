# BakaSU F06 — persistent signer and promoted reserved source

F06 is a manual hosted diagnostic gate, not publication, installation, or root
manager authorization. It never makes another disposable upstream integration
merge. F05 and the single-writer GAP-03 journal establish exact promotion and
version evidence; F06 consumes a reservation from that journal.

## Review and protected setup

1. Complete the F05 diagnostic build, native reviewed promotion and merge, then
   `reserve-version` in the persistent owner journal. Preserve the journal;
   never initialize it again to recover a response. Export the immutable row:
   `python3 -B scripts/fork/journal_cli.py --journal "$JOURNAL" export-signing-reservation --event-key "$EVENT_KEY"`.
   This is read-only output, not approval. Record the actual source and test
   evidence for the exact promoted commit/tree and the diagnostic run/artifact.
2. Create or retain the persistent fork signer outside the repo. Keep a private
   offline backup and independently verify the SHA-256 of its DER certificate.
   The `fork-signing` GitHub environment must be protected by human review.
   Provision these five environment secrets, without logging any secret values:
   `FORK_SIGNER_KEYSTORE_B64`, `FORK_SIGNER_STORE_PASSWORD`,
   `FORK_SIGNER_KEY_ALIAS`, `FORK_SIGNER_KEY_PASSWORD`,
   `FORK_SIGNER_CERT_SHA256`. The latter is the certificate fingerprint, not the
   keystore or APK checksum. No automatic production key generation or rotation.
3. Through a separately qualified and reviewed native overlay, set
   `certificateSha256` in `config/fork-signing-contract.json` to the independently
   reviewed certificate SHA-256 and append the exact exported row to
   `approvedReservations`. The committed policy is initially null/empty; do not
   fabricate a row or certificate. Retain all historical approved rows and the
   same cert; rotation/removal requires separate reviewed governance. Merge and
   record the exact new main workflow SHA.
4. Dispatch **Fork F06 — Source-Pinned Signed Manager Qualification** on `main`
   with `reservation_id`, `version_code`, and `fork_sha` equal to that committed
   policy identity and main SHA. The runner verifies remote main, committed
   ancestry/tree, the original F05 artifact/run, the global published version
   floor, and historical signer continuity, then checks out exactly the
   promoted commit in a private worktree. It runs existing source/regression
   checks there before signing. The reserved Gradle version is passed only for
   package `com.mikeyphw.bakasu`. No local Gradle build is permitted.
5. F06 verifies the actual keystore DER digest before unlocking Gradle, keeps
   temporary key material and properties private, restores properties and
   deletes the temporary keystore even on failure. It verifies actual APK v2
   signatures, exactly one signer, package, reserved version, filename and
   native ABI inventory on every APK. It uploads only the report and APKs, with
   exact run/attempt-specific names. Neither output qualifies device or release.

Review both `f06-source-and-signer-evidence-<run>-<attempt>` and
`f06-signed-manager-diagnostic-<run>-<attempt>` artifacts and record their
provider IDs/digests plus the raw signed report SHA-256 for F07. Preserve the
original provider archives outside the temporary runner before retention expiry.
Actual protected hosted signer/build acceptance remains an owner-controlled gate.
