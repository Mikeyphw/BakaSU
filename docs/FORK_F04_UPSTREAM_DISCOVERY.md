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

The scheduled F04 workflow remains **discovery-only**. Repeated scheduled reports may contain the same candidate. The separate owner-side GAP-03 journal persists processed-event identities and bounded replay checkpoints; no transient CI artifact is treated as its durable store. No hosted dispatch authority is added.

Do not install any F01–F04 debug APK as the daily manager. Real-device authorization and persistent release signing are still pending. The F01–F03 module Reinstall and kernel compatibility patches stay in the PR.

### Example report fields

Each candidate contains `key`, `channel` (`beta` or `stable`), `upstreamSha`, `eventAt`, and `upstreamUrl`. Betas include `upstreamRunId`; stable releases include `upstreamTag` and `upstreamReleaseId`.

### Review and test

```
python3 -B -m unittest discover -s scripts/fork/tests -p 'test_*.py' -v
python3 -B scripts/fork/source_contract.py --check
```

Use source-qualified native Devtool delivery for changes to the discovery workflow. No local Gradle compilation or root/device operations.
