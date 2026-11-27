# GAP-03 — durable event and promotion review

This source change separates the scheduled read-only discovery report from the single owner-controlled durable journal. The journal must live in a private persistent directory, not a CI workspace, cache, or temporary artifact. No new hosted write permission is introduced. An operator or owner schedule must explicitly invoke the journal; this source alone does not provision such a schedule. A journal shared by multiple machines requires an independently reviewed single-writer coordination/storage design.

## Recovery semantics

- Initialize one journal from an explicitly reviewed checkpoint and version floor. Never reset an existing journal to recover a lost response. Preserve its bytes, permissions and history.
- Discover in bounded seven-day windows from the persisted checkpoint, with one-hour overlap. Continue additional windows after a long outage; do not jump directly to the current date. Unsettled beta runs hold the checkpoint; ambiguous/truncated provider listings refuse progress. The journal currently has a bounded event capacity and requires separately reviewed archival/continuation before exhausting it.
- `status` is local read-only. `discover` persists discovery results. `reconcile` observes exact authenticated run identities. `dispatch` and `tick` need explicit approval and the actual fork main SHA. A durable intent is written before dispatch; an absent run after an ambiguous response is not proof that no dispatch happened. It remains held rather than retried automatically. No production schedule or provider mutation is implied by the local tests.
- A known failed attempt can be retried only on a different fork source and only up to the bounded attempt limit. A moved tag, source drift, corrupt journal or unsafe path refuses the operation.

## Promotion and version evidence

The F05 diagnostic job exports the real merged Git objects and provenance, including the tree, source identities and APK checksums. `plan-promotion` verifies an authenticated provider artifact's digest and run identity, imports its bundle in a disposable bare repository, and produces an exact review inventory. It does not apply source changes or authorize a PR. An independent native Devtool source-qualified overlay and reviewed merge are still required to promote that inventory. Changed main, unexpected file modes, unsafe paths, and inventories outside the supported limit refuse promotion rather than approximate the source tree.

`reserve-version` requires the exact integrated tree in a committed ancestor of the current canonical main and a fresh published-release floor. One journal counter covers stable and beta. The reservation is never claimed to be a signed or published release. The restricted Gradle property is a build input for the fork package; signed-build consumption and release verification remain later acceptance work. Local Gradle is prohibited; the actual Android build is a hosted gate.

## Qualification boundaries

The journal tests exercise actual local file persistence, failure injection and disposable Git repositories. Provider responses are controlled fixtures. No hosted run, production dispatch, live promotion, signing, release publication, or physical-device behavior is established by these tests.
