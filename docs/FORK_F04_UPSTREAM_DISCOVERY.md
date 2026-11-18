# BakaSU Fork F04 — read-only upstream discovery

Target: `Mikeyphw/BakaSU`, branch `feature/f01-fork-manager-baseline-20261115`.

## Included

- A GitHub Actions workflow scheduled every 15 minutes **after it lands on the default branch**. GitHub's scheduler may delay executions.
- A read-only, standard-library Python GitHub API poller for upstream `Baka-SU/BakaSU`.
- Beta candidates only from **successful completed upstream `build-manager.yml` push runs on `main`**, with real 40-character source SHAs.
- Stable candidates only from **published non-draft, non-prerelease upstream `v*` releases**; lightweight and annotated tags are resolved to source commits.
- Bounded lookback (seven days by default), bounded pagination, duplicate beta-SHA elimination, and explicit failure for incomplete or ambiguous API results.
- Immutable report artifacts from each successful run containing source SHAs, event IDs, tags, provenance URLs, and discovery keys. No secrets are printed.
- Fake-GitHub regression tests run without GitHub API calls.

## Important boundaries

F04 is **discovery-only**. It **does not** yet dispatch builds, maintain an across-run processed-event ledger, merge upstream code, sign APKs, publish releases, or modify the app. Repeated scheduled runs can therefore report the same candidate. Source-qualified build dispatch, persistent event deduplication, and safe upstream integration belong to F05–F07.

Do not install any F01–F04 debug APK as the daily manager. Real-device authorization and persistent release signing are still pending. The F01–F03 module Reinstall and kernel compatibility patches stay in the PR.

### Example report fields

Each candidate contains `key`, `channel` (`beta` or `stable`), `upstreamSha`, `eventAt`, and `upstreamUrl`. Betas include `upstreamRunId`; stable releases include `upstreamTag` and `upstreamReleaseId`.

### Review and test

```
python3 -B -m unittest discover -s scripts/fork/tests -p 'test_*.py' -v
python3 -B scripts/fork/source_contract.py --check
```

Run the F04 overlay's `inspect` first; it validates the exact fork branch, source SHA and clean worktree, with no Git mutations. `apply` commits and pushes the new detector/test/workflow and a path-trigger adjustment to `fork-manager-ci.yml` via your configured Git SSH. No local Gradle compilation or root/device operations.
