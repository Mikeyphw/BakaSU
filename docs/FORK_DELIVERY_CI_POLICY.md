# BakaSU fork — committed Devtool delivery CI policy

Repository: `Mikeyphw/BakaSU` · target branch: `feature/f01-fork-manager-baseline-20261115` · PR #1.
This repair follows F05's already committed and pushed source `25ee23c91be6aebd8c009c8460b5ed92a1a05823`.

## Required checks

`config/delivery-required-ci.json` declares the exact active provider workflow IDs:

- `Fork Manager Baseline Qualification` — `420307178` (Python contracts, Spotless, manager debug build and whitespace)
- `Lints Check` — `420303004` (upstream formatter, Rust/C and manager lint checks)

Both workflows must register for every `pull_request`, including policy-only changes.
The baseline's previous `pull_request.paths` filter has been removed because
Devtool's native CI registrar cannot prove a path-filtered required workflow
will be triggered for every commit; it fails closed rather than counting skips.
No tests or gates are removed, and the existing `workflow_dispatch` remains.

`CodeQL` (`420306787`) remains enabled for manager changes but has manager-only
path filters. It is supplemental, not declared universally required, because
Devtool correctly refuses uncertain conditional registration. If universal
CodeQL becomes an explicit acceptance requirement, update its trigger and this
policy together, without guessing runs or treating skips as passes.

## Delivery and recovery

This is a new source-pinned native Devtool overlay. The F05 source commit and
durable session `340cd09a843543b09a5c16432bd24620` are **not replayed**.
The new v3.1 source-pinned .pyz is generated using the canonical builder on
Termux and applied only through native `validate overlay` / `apply overlay`.
The policy is now committed; the source-bound v3.1 launcher may run
`apply --approve-remote --watch-ci`. The resulting **new** delivery session
is authoritative; never reuse the old-fork session or replay F05.
A non-green CI result does not undo a committed push.

The CI policy verifies hosted tests on the actual new PR commit; it does not
qualify signing, installation, devices, releases, or automatic merging.

## Remaining limitations

GitHub Actions workflow registration may be delayed or disabled. No local tests
are accepted as a substitute for the actual published PR HEAD, and old green
workflow runs do not count. F05's debug APK remains a CI diagnostic artifact.

## GitHub fork identity after refork (2026-11-16)

New repository ID: `1460223693` (parent `Baka-SU/BakaSU`). GitHub reassigns workflow IDs
on a new fork, even when workflow paths and names are unchanged.
The post-refork required identities are manager `420307178`, lint `420303004`
and supplemental CodeQL `420306787`. Both required workflows must
register and pass on the exact **new PR HEAD**; old-fork runs,
receipts and PR numbers never qualify the new GitHub repository.
Use native Devtool delivery status/ci against the new session.
Do not treat CI, debug artifacts, signing or device tests as interchangeable.

## Rust formatting workflow: maintained blocking gate

The required `Lints Check` workflow keeps the job name `Rustfmt check` and
checks both `userspace/ksud` and `userspace/ksuinit` with **direct**
`cargo +nightly fmt --all --manifest-path ... -- --check` commands.
The shell exits on any formatter failure; the third-party
`LoliGothick/rustfmt-check@master` JavaScript wrapper was removed after a
PR-only Node runtime `TypeError` (Actions run `43929420726`, job
`133517549139`) obscured the actual formatter result.
No Rust formatting, lint, Android or security assurance is waived.
`test_rustfmt_ci_contract.py` is discovered by the existing hosted
`test_*.py` suite and includes negative cases for missing workspaces,
missing `--check`, suppressed exit status, removed required jobs and return of
the obsolete wrapper. The required workflow's provider ID and trigger remain
unchanged. A passing push run does not replace a failing PR run; qualify the
**new** PR HEAD only after both required workflows complete successfully.
F06 persistent-key signing, releases and physical device validation are
separate milestones and are not established by this CI repair.
