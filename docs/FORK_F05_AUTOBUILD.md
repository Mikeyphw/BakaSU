# BakaSU fork F05 — source-pinned upstream manager integration

Repo: `Mikeyphw/BakaSU` · PR #1 · based on F01–F04. All builds are GitHub-hosted.

## How it works (after merge to `main`)

1. `fork-upstream-discovery.yml` runs every 15 minutes (GitHub scheduling may be delayed), discovers upstream successful beta `Build Manager` push events and stable releases, and writes its F04 evidence artifact.
2. F05 dispatcher checks `fork-source-build.yml` run history for the exact **channel / upstream commit / fork commit** combination. It submits up to four unseen jobs per scan. Previously observed *failed* jobs are held for review; no repeated failures on every poll.
3. Each dispatched F05 job independently revalidates the upstream event by ID and 40-character source SHA. Stable release tags are dereferenced, including annotated tags. An event mismatch fails closed.
4. Actions checks out exactly the expected fork `main` source, fetches the upstream source commit and merges it in the disposable runner checkout. **Merge conflicts refuse** and are reported; the runner never force-pushes, resets a user's branch or modifies `main`.
5. The existing fork source contracts, regression tests and Kotlin formatter are rerun on the *integrated source*, followed by manager-only `:app:assembleDebug`. No kernel matrix, local Gradle or release signing.
6. Provenance JSON records the input source/event IDs, the fork SHA, integrated git tree and debug APK SHA-256. A debug APK is retained as a temporary CI diagnostic artifact, **not** a user-installable release.

## Failure policy

- GitHub API ambiguity, missing token, wrong branch, source drift, wrong workflow, unsuccessful beta, draft/prerelease stable, mismatched release tag, incomplete run history, merge conflict, broken source contract, formatting failure or APK build failure blocks progression.
- F04 discovery artifacts remain available. F05 provenance artifacts are produced on source-stage failure.
- The dispatcher does **not** blindly retry failed source combinations; review its failed run and dispatch again intentionally if appropriate.
- GitHub Actions event discovery and workflow dispatch are active only when these workflows are in the fork's default branch. A PR build tests Python code and YAML but does not invoke the live automation.
- The scheduled scan uses a rolling seven-day discovery window and bounded pagination; a long outage may require manual replay.
- `GITHUB_TOKEN` needs `actions: write` only in the F04 discovery workflow. The build workflow is `contents: read` and never pushes.

## Release boundaries

**F05 does not produce a signed production APK or an in-app update release.** Persistent signing, published fork-only APKs, atomic release metadata, version-code policy, and on-device manager authorization belong to F06/F07/F09. Do not install the diagnostic debug APK as your daily root manager.

## Checks

```sh
python3 -B -m unittest discover -s scripts/fork/tests -p 'test_*.py' -v
python3 -B scripts/fork/source_contract.py --check
```

Only GitHub Actions may invoke Gradle. Source-pinned overlay must pass `self-test` and `inspect` before `apply` commits/pushes the existing draft PR branch.
