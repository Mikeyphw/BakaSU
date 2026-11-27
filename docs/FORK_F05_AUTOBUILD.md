# BakaSU fork F05 — source-pinned upstream manager integration

Repo: `Mikeyphw/BakaSU` · PR #1 · based on F01–F04. All builds are GitHub-hosted.

## How it works (after merge to `main`)

1. `fork-upstream-discovery.yml` runs every 15 minutes (GitHub scheduling may be delayed), discovers upstream successful beta `Build Manager` push events and stable releases, and writes its F04 evidence artifact.
2. The owner-side durable journal records exact event identities and persists a dispatch intent before any F05 POST. It adopts exact observed runs, submits at most four pending events per approved invocation and never automatically replays an uncertain dispatch. The scheduled F04 workflow remains read-only.
3. Each dispatched F05 job independently revalidates the upstream event by ID and 40-character source SHA. Stable release tags are dereferenced, including annotated tags. An event mismatch fails closed.
4. Actions checks out exactly the expected fork `main` source, fetches the upstream source commit and merges it in the disposable runner checkout. **Merge conflicts refuse** and are reported; the runner never force-pushes, resets a user's branch or modifies `main`.
5. The existing fork source contracts, regression tests and Kotlin formatter are rerun on the *integrated source*, followed by manager-only `:app:assembleDebug`. No kernel matrix, local Gradle or release signing.
6. Provenance JSON records the input source/event IDs, the fork SHA, integrated git tree and debug APK SHA-256. A debug APK is retained as a temporary CI diagnostic artifact, **not** a user-installable release.

## Failure policy

- GitHub API ambiguity, missing token, wrong branch, source drift, wrong workflow, unsuccessful beta, draft/prerelease stable, mismatched release tag, incomplete run history, merge conflict, broken source contract, formatting failure or APK build failure blocks progression.
- F04 discovery artifacts remain available. F05 provenance artifacts are produced on source-stage failure.
- A known failed attempt can be retried only against a different verified fork source, with at most three attempts per event. An uncertain result is held for reconciliation.
- GitHub Actions event discovery and workflow dispatch are active only when these workflows are in the fork's default branch. A PR build tests Python code and YAML but does not invoke the live automation.
- The scheduled report uses a rolling seven-day window; the owner journal replays from its persisted checkpoint in bounded seven-day windows, including overlap and unresolved-run holds.
- F04 and F05 hosted workflows do not dispatch or push. Explicitly authorized owner-side dispatch needs a token with workflow-dispatch permission; read-only status and promotion review do not require repository write permission.

## Release boundaries

**F05 does not produce a signed production APK or an in-app update release.** Persistent signing, published fork-only APKs, consumption of the reserved version in the signed build, atomic release metadata and on-device manager authorization remain separate F06/F07/F09 gates. Do not install the diagnostic debug APK as your daily root manager.

## Checks

```sh
python3 -B -m unittest discover -s scripts/fork/tests -p 'test_*.py' -v
python3 -B scripts/fork/source_contract.py --check
```

Only GitHub Actions may invoke Gradle. Source changes require the native Devtool source-qualified overlay lifecycle and a reviewed PR. See `fork-gap03-qualification.md` for the journal and promotion evidence boundaries.

## GAP-04 signing transition

The GAP-03 owner journal is the durable authority. After exact native promotion and reservation, use its read-only `export-signing-reservation` command and separately review the emitted immutable row and persistent certificate in the F06 policy. Do not re-integrate upstream in F06. See `FORK_F06_SIGNED_QUALIFICATION.md`.
