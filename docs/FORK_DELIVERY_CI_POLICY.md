# BakaSU fork — committed Devtool delivery CI policy

Repository: `Mikeyphw/BakaSU` · target branch: `feature/f01-fork-manager-baseline-20261115` · PR #1.
This repair follows F05's already committed and pushed source `25ee23c91be6aebd8c009c8460b5ed92a1a05823`.

## Required checks

`config/delivery-required-ci.json` declares the exact active provider workflow IDs:

- `Fork Manager Baseline Qualification` — `419472937` (Python contracts, Spotless, manager debug build and whitespace)
- `Lints Check` — `419472876` (upstream formatter, Rust/C and manager lint checks)

Both workflows must register for every `pull_request`, including policy-only changes.
The baseline's previous `pull_request.paths` filter has been removed because
Devtool's native CI registrar cannot prove a path-filtered required workflow
will be triggered for every commit; it fails closed rather than counting skips.
No tests or gates are removed, and the existing `workflow_dispatch` remains.

`CodeQL` (`419492297`) remains enabled for manager changes but has manager-only
path filters. It is supplemental, not declared universally required, because
Devtool correctly refuses uncertain conditional registration. If universal
CodeQL becomes an explicit acceptance requirement, update its trigger and this
policy together, without guessing runs or treating skips as passes.

## Delivery and recovery

This is a new source-pinned native Devtool overlay. The F05 source commit and
durable session `340cd09a843543b09a5c16432bd24620` are **not replayed**.
The new v3.1 source-pinned .pyz is generated using the canonical builder on
Termux and applied only through native `validate overlay` / `apply overlay`.
The v3.1 preflight requires this committed CI policy **before** `--watch-ci`,
so initial policy onboarding uses native apply without CI watch; the returned
new session is the authority for subsequent `ci`, `status` and `report`.
A non-green CI result does not undo a committed push.

The CI policy verifies hosted tests on the actual new PR commit; it does not
qualify signing, installation, devices, releases, or automatic merging.

## Remaining limitations

GitHub Actions workflow registration may be delayed or disabled. No local tests
are accepted as a substitute for the actual published PR HEAD, and old green
workflow runs do not count. F05's debug APK remains a CI diagnostic artifact.
