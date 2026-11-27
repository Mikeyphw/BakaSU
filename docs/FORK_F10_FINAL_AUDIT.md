# F10 — final R9 reconciliation and retained replay

Run from clean full-history main with authenticated read-only `gh` and an
owner-private evidence directory. The final audit compares the committed
signing/review policies, exact promoted trees, optional actual local journal,
complete bounded release inventory, tag identity, stable/beta monotonic
version ordering, exact main-push required CI, scheduled discovery and
reviewed F05 diagnostic provider identities. It emits all ten original R9
milestones. It never makes a dispatch, reserves a version, publishes, changes
keys or performs device operations. Missing external proof is not success.

```sh
python3 -B scripts/fork/f10_reconcile.py audit --output "$evidence/r9-audit.json"
```

Add `--journal "$journal_path"` for the actual durable journal and
`--references "$references"` for live F08 records. The index schema is
`{"schemaVersion":1,"references":[{"tag":"...","runId":123,"runAttempt":1,"artifactId":456}]}`;
IDs shown are examples, never approval. A missing journal or F08 record is
reported as pending. Unreviewed manager releases, moved tags, duplicate or
truncated inventory, nonmonotonic versions and altered reservations refuse.
No release means there is no published version-order evidence; no device
acceptance is inferred from the audit.

Before original Actions artifacts expire, preserve an immutable evidence
bundle with Android SDK build-tools (`aapt`, `apksigner`) available. Use a
single F08 reference JSON (not the index):

```sh
python3 -B scripts/fork/f10_reconcile.py retain --reference "$reference" --folder "$evidence/retained-release" --sdk "$ANDROID_HOME" --output "$evidence/retention.json"
python3 -B scripts/fork/f10_reconcile.py replay --folder "$evidence/retained-release" --sdk "$ANDROID_HOME" --output "$evidence/replay.json"
```

Retention downloads the exact F08 and original F06 ZIPs, provider metadata
and every published asset by ID; it re-verifies source, tags, sizes, digests,
APK signatures and exact compatibility. A final manifest binds all retained
bytes. Existing directories are not replaced. Preserve the verified manifest
hash independently alongside durable backup of the evidence. Replay repeats
byte/signature and committed-source checks with the historical provider
observations; local provider records are not fresh authenticated remote proof.
An offline replay explicitly remains historical, never substitutes for a
new live F08 audit, and never establishes physical-device/root acceptance.
