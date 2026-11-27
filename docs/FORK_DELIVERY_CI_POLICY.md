# BakaSU fork — committed Devtool delivery CI policy

## Current repository identity and required workflow registrations

Repository: `Mikeyphw/BakaSU`, GitHub repository ID `1462243855`, default branch `main`.
The former fork ID `1460223693` and its old workflow IDs must not be used.
Authenticated Actions run history (2026-11-27) binds the following workflow IDs
and paths to the restored repository:

| Workflow | ID | Historical evidence |
|---|---:|---|
| Fork Manager Baseline Qualification | 422131211 | run 44312475887, PR |
| Lints Check | 422130394 | run 44312476061, PR; run 45935721171, push |
| CodeQL (supplemental) | 422131210 | run 44312475914, PR |
| Fork Upstream Discovery (F04) | 422668545 | run 45931928483, schedule |
| Fork Source-Pinned Manager Build (F05) | 422668538 | run 45890689648, dispatch |
| Fork F06 — Source-Pinned Signed Manager Qualification | 422668529 | run 44320446153, dispatch |

The first two are required by `config/delivery-required-ci.json`; they have
unconditional PR triggers, independent push verification, and manual dispatch.
Observed IDs do not establish current registration state. The remaining nine
source workflow paths are inventoried in `config/fork-ci-workflows.json` without
inventing provider IDs. The inherited `check-line-ending.yml` is not a source
file: the actual line-ending gate remains within Lints Check.

## Read-only registration reconciliation

The shared source gate runs `python3 -B scripts/fork/ci_inventory.py` and checks
the complete source roster. It deliberately reports `registration_status: NOT_CHECKED`
unless actual provider evidence is supplied. Both required workflows invoke
`ci_inventory.py --github-api` with read-only contents/actions permission after
the source gate, before expensive fan-out; a failed provider GET or missing
required registration blocks qualification. In an authenticated owner terminal,
collect repository metadata and the complete paginated Actions workflow registry
using `gh api repos/Mikeyphw/BakaSU` and
`gh api --paginate --slurp repos/Mikeyphw/BakaSU/actions/workflows` into private
JSON files. Run `ci_inventory.py --repository-json REPO_JSON --registrations-json WORKFLOWS_JSON`.
A missing, inactive, renamed or wrong-ID required workflow is a failure. Other
missing or unexpected registrations are separately marked `REVIEW_REQUIRED`;
the tool is read-only and never enables, dispatches or modifies workflows.
Protected release and inherited kernel workflows require separate authorization.

## Source-first dependency graph

Both required workflows run a shared strict checkout, inventory, source contract,
full fork unittest and changed-line whitespace check before costly fan-out.
Every child validates its own checkout against the run's GitHub SHA. The
original manager debug, Spotless, ClangFormat, Rustfmt (both workspaces), Clippy,
ShellCheck, line ending and Android lint contexts remain intact. Independent
aggregate jobs fail unless every prerequisite and child reports `success`;
skipped, cancelled, failed or missing results are not success. No local Gradle.
CodeQL retains its supplemental path filters and duplicate suppression for
non-scheduled events; the prerequisite itself always runs, including scheduled
events, and its failure prevents analysis. Scheduled analysis is not suppressed
by the duplicate-check step.

The actual Android lint failure on run 45935721171 was dependency download HTTP
429 (Maven Central), wrapped in a Gradle configuration-cache serialization error.
The hosted-only lint route uses `lintDebug --no-configuration-cache --no-daemon
--stacktrace`, preserves the original failure, and retries only an identified
Maven Central download HTTP 429, at most twice with 15/30-second delays. No
Gradle task, lint finding, compiler warning, source test or real failure is waived.
The existing Gradle cache setup remains. The actual native `make check-format`
gate is unchanged and now prints the formatter version; the hosted ClangFormat
failure must be resolved and reverified,
not treated as a dependency outage or suppressed. No automatic formatting commit.

## Devtool integration and acceptance

`.devtool.toml` declares the Python runner and the actual fork unittest command,
which does not execute local Gradle or kernel builds. Apply source modifications
through the current source-bound Devtool native lifecycle on a named feature
branch. A current exact-PR-head required CI result and independent CI24 are
separate from local regression evidence. Do not replay historical delivery
sessions or count historical successful runs as current qualification.

F04 scheduled discovery is observed working after merge. F05's latest failure
is a real upstream merge conflict; keep the fail-closed integration behavior and
handle durable reviewed promotion in GAP-03. Signing, release registration,
physical-device qualification and automatic merging remain separate and are not
approved or proven here. No source promotion, release or signing mutation is
part of this CI policy repair.

### Mixed native source qualification (GAP-01)

The existing two locked Rust workspaces, nested Gradle 9.8.0 manager,
reviewed kernel Makefile/DDK matrix, and JS package are separate native
qualification roots. The WebUI library now has an offline dependency-free
lockfile, real Node tests, strict declaration compilation and an ESLint gate.
`test_bakasu_native_layout.py` exercises safe host-only shell and C fixtures;
no Android installer, real kernel build, or Gradle task runs as a side effect
of the Python test suite. Hosted Android, kernel and device evidence remain
separate; a missing tool is not a successful native check.
