# F07 — reviewed, source-pinned BakaSU publication

Manual-only `workflow_dispatch` on fork main, protected by `fork-release` with
human reviewers. Never triggered by tags, pushes, F05 or F06. The `f07-v` tag
prefix avoids the inherited `v*` release automation.

## Review

After real protected F06 success, append a separately reviewed schema-2 entry to
`config/fork-release-review.json`, preserving every earlier entry. Required keys:

- `f06RunId`, `f06RunAttempt`, `tag`, `channel`, `sourceMergedSha` (actual
  committed promoted source), `sourceForkSha` (F06 workflow main), `sourceTree`;
- `reservationId`, `versionCode`, `certificateSha256`, `managerUapi`,
  `minimumKernelSuVersion` (compatibility values from reviewed source/test
  evidence, never inferred from a device or invented);
- `signedProvenanceSha256` (raw original F06 report bytes), `evidenceArtifactId`,
  `evidenceArtifactSha256`, `apkArtifactId`, `apkArtifactSha256` (original exact
  attempt provider archive identity). Artifact digests are lowercase hex without
  the API's `sha256:` prefix.

The initial registry is empty; this source change does not authorize any real
release. Every entry is bound to the actual F06 reviewed reservation and fixed
signer policy at the signing commit and at current main. Retain historical rows;
changes/removal/rotation require a separate reviewed migration. F07 verifies
provider run/attempt/name/digest and downloads both original ZIPs by immutable
artifact ID, hashes raw archive bytes before extracting a bounded flat inventory,
rechecks APK hashes, native ABIs, package, version, v2 and signer, and verifies
committed tree/ancestry. It also generates the F03 compatibility manifest and
retains the original signed report as a published asset.

## Publication and recovery

Dispatch **Fork F07 — Reviewed Signed Manager Release** with the reviewed run
ID, tag, channel and `resume=false` for a new transaction. The global release
history must be unambiguous, all APK versions recognized, and the version code
strictly above all published stable/beta versions. Fresh publication is allowed
only on the first attempt with no earlier observed intent for that tag. Before
any write, confirm exact remote main and a nonexistent tag/release. The protected
workflow creates one draft, reads the exact transaction identity and downloads
all assets by immutable asset ID to verify actual bytes, then publishes the
exact complete draft and independently rechecks the published tag and assets.

An ambiguous response never automatically retries creation. After reviewing the
original run and observed exact draft or published release, dispatch explicitly
with `resume=true`. Resume never creates a new transaction. It refuses missing,
foreign or mismatched release identities and unsafe asset sets; may upload only
missing exact approved assets without clobber; and verifies a previously
published exact transaction without publishing again. If no matching release is
observable after an ambiguous response, stop for separate incident review; do
not delete a draft/tag or recreate it to force progress. Rechecking main before
writes and serializing F07 do not authorize other release writers; prevent
out-of-band publication in the owner-controlled repository.

No production signing key, real release or device has been qualified by these
source tests. F08 is a separate read-only audit; F09 is separate device/root
qualification. Run F08 while original provider archives remain available and
retain its report and the original immutable archives for later incident review.
