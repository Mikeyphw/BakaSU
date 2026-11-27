"""Exercise production CI identity, graph, inventory and bounded hosted lint routes."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts/fork"))
import ci_gate
import ci_inventory


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.expected = ci_inventory.source_inventory()
        self.repo = {"id": 1462243855, "full_name": "Mikeyphw/BakaSU", "default_branch": "main"}
        self.actual = []
        for index, entry in enumerate(self.expected.values(), 1):
            self.actual.append({"id": entry.get("workflow_id", entry.get("observed_workflow_id", index)),
                                "name": entry["name"], "path": entry["path"], "state": "active"})

    def check(self, rows=None):
        rows = self.actual if rows is None else rows
        pages = [{"total_count": len(rows), "workflows": rows[:7]},
                 {"total_count": len(rows), "workflows": rows[7:]}]
        return ci_inventory.reconcile(self.expected, self.repo, pages)

    def test_complete_registration(self):
        result = self.check()
        self.assertEqual(len(result["workflows"]), 15)
        self.assertEqual(result["required_status"], "PASS")
        self.assertEqual(result["inventory_status"], "PASS")

    def test_missing_or_inactive_required_registration_fails(self):
        path = ".github/workflows/fork-manager-ci.yml"
        self.assertEqual(self.check([r for r in self.actual if r["path"] != path])["required_status"], "FAIL")
        for row in self.actual:
            if row["path"] == path:
                row["state"] = "disabled_manually"
        self.assertEqual(self.check()["failed_required_paths"], [path])

    def test_stale_id_and_name_refuse(self):
        for key, val in (("id", 420307178), ("name", "Renamed")):
            rows = copy.deepcopy(self.actual)
            next(r for r in rows if r["path"].endswith("fork-manager-ci.yml"))[key] = val
            self.assertEqual(self.check(rows)["required_status"], "FAIL")

    def test_unregistered_nonrequired_reported_not_enabled(self):
        rows = [r for r in self.actual if not r["path"].endswith("fork-f07-release.yml")]
        result = self.check(rows)
        self.assertEqual(result["required_status"], "PASS")
        self.assertEqual(result["inventory_status"], "REVIEW_REQUIRED")
        self.assertEqual(next(r for r in result["workflows"] if r["path"].endswith("fork-f07-release.yml"))["status"], "MISSING")

    def test_unknown_registration_reported(self):
        rows = self.actual + [{"path": ".github/workflows/check-line-ending.yml", "id": 987,
                               "name": "old", "state": "disabled_manually"}]
        self.assertEqual(self.check(rows)["unexpected_registrations"], [".github/workflows/check-line-ending.yml"])

    def test_wrong_repository_refused(self):
        self.repo["id"] = 1460223693
        with self.assertRaises(ValueError):
            self.check()

    def test_incomplete_pagination_and_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            ci_inventory.reconcile(self.expected, self.repo, [{"total_count": 15, "workflows": self.actual[:7]}])
        for row in (self.actual[0], dict(self.actual[0], path="other")):
            with self.assertRaises(ValueError):
                self.check(self.actual + [row])

    def test_duplicate_json_keys_refused(self):
        with self.assertRaises(ValueError):
            json.loads('{"id":1,"id":2}', object_pairs_hook=ci_inventory.unique_object)

    def test_provider_get_calls_are_read_only_and_fail_closed(self):
        pages = [{"total_count": len(self.actual), "workflows": self.actual}]
        result = lambda obj: subprocess.CompletedProcess([], 0, json.dumps(obj).encode(), b"")
        with patch.object(ci_inventory.subprocess, "run", side_effect=[result(self.repo), result(pages)]) as run:
            repo, received = ci_inventory.read_provider()
            self.assertEqual(ci_inventory.reconcile(self.expected, repo, received)["required_status"], "PASS")
            self.assertEqual([x.args[0] for x in run.call_args_list], [
                ["gh", "api", "repos/Mikeyphw/BakaSU"],
                ["gh", "api", "--paginate", "--slurp", "repos/Mikeyphw/BakaSU/actions/workflows"],
            ])
        with patch.object(ci_inventory.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"private")):
            with self.assertRaisesRegex(ValueError, "read-only registration request failed"):
                ci_inventory.read_provider()

    def test_unknown_source_workflow_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / ".github/workflows").mkdir(parents=True)
            for name in ("fork-ci-workflows.json", "delivery-required-ci.json"):
                (root / "config" / name).write_bytes((ROOT / "config" / name).read_bytes())
            for path in self.expected:
                (root / path).write_bytes((ROOT / path).read_bytes())
            self.assertEqual(len(ci_inventory.source_inventory(root)), 15)
            (root / ".github/workflows/unreviewed.yml").write_text("name: unreviewed\n")
            with self.assertRaises(ValueError):
                ci_inventory.source_inventory(root)


class SourceGateTests(unittest.TestCase):
    def test_exact_sha_admission(self):
        sha = "a" * 40
        with patch.object(ci_gate, "git", return_value=sha):
            self.assertEqual(ci_gate.verify_checkout(sha), sha)
            for invalid in ("", "a" * 39, "b" * 40, "--help"):
                with self.assertRaises(ValueError):
                    ci_gate.verify_checkout(invalid)

    def test_source_gate_runs_exact_real_commands_and_stops_on_failure(self):
        sha = "a" * 40
        with patch.object(ci_gate, "verify_checkout", return_value=sha), \
             patch.object(ci_gate, "diff_args", return_value=["diff", "--check", sha, sha]), \
             patch.object(ci_gate.subprocess, "run") as run:
            ci_gate.source_gate({"GITHUB_SHA": sha})
            self.assertEqual(len(run.call_args_list), 4)
            self.assertIn("scripts/fork/ci_inventory.py", run.call_args_list[0].args[0])
            self.assertIn("scripts/fork/source_contract.py", run.call_args_list[1].args[0])
            self.assertIn("test_*.py", run.call_args_list[2].args[0])
            self.assertEqual(run.call_args_list[3].args[0][:3], ["git", "diff", "--check"])
            self.assertTrue(all(x.kwargs["check"] for x in run.call_args_list))
            run.reset_mock()
            run.side_effect = [None, subprocess.CalledProcessError(7, "test")]
            with self.assertRaises(subprocess.CalledProcessError):
                ci_gate.source_gate({"GITHUB_SHA": sha})
            self.assertEqual(run.call_count, 2)

    def test_pr_diff_refuses_partial_and_unrelated_identity(self):
        a, b, c = (letter * 40 for letter in "abc")
        with self.assertRaises(ValueError):
            ci_gate.diff_args(c, {"PR_BASE_SHA": a})
        with patch.object(ci_gate.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "ancestor")):
            with self.assertRaises(subprocess.CalledProcessError):
                ci_gate.diff_args(c, {"PR_BASE_SHA": a, "PR_HEAD_SHA": b})
        with patch.object(ci_gate.subprocess, "run") as run:
            self.assertEqual(ci_gate.diff_args(c, {"PR_BASE_SHA": a, "PR_HEAD_SHA": b}),
                             ["diff", "--check", a, b, "--"])
            self.assertEqual(run.call_count, 2)

    def test_push_before_and_manual_parent(self):
        a, b = "a" * 40, "b" * 40
        with patch.object(ci_gate, "git", return_value=a + " " + b):
            self.assertEqual(ci_gate.diff_args(a, {}), ["diff", "--check", b, a, "--"])
            self.assertEqual(ci_gate.diff_args(a, {"PUSH_BEFORE_SHA": b}), ["diff", "--check", b, a, "--"])
        with self.assertRaises(ValueError):
            ci_gate.diff_args(a, {"PUSH_BEFORE_SHA": "bad"})


class LintRetryTests(unittest.TestCase):
    def setUp(self):
        self.env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_SHA": "a" * 40}

    def run_fixture(self, results):
        run, sleep = Mock(side_effect=results), Mock()
        with patch.object(ci_gate, "verify_checkout", return_value="a" * 40):
            rc = ci_gate.hosted_lint(self.env, run=run, sleep=sleep)
        self.assertEqual(run.call_args.args[0], ["./gradlew", "lintDebug", "--no-configuration-cache", "--no-daemon", "--stacktrace"])
        return rc, run.call_count, [x.args[0] for x in sleep.call_args_list]

    def test_success_and_non_network_failure(self):
        self.assertEqual(self.run_fixture([(0, False)]), (0, 1, []))
        self.assertEqual(self.run_fixture([(7, False)]), (7, 1, []))
        self.assertEqual(self.run_fixture([(-15, False)]), (143, 1, []))

    def test_retry_only_rate_limited_and_bounded(self):
        self.assertEqual(self.run_fixture([(1, True), (0, False)]), (0, 2, [15]))
        self.assertEqual(self.run_fixture([(1, True), (2, True), (3, True)]), (3, 3, [15, 30]))
        self.assertEqual(self.run_fixture([(1, True), (5, False)]), (5, 2, [15]))

    def test_local_gradle_refused_before_runner(self):
        run = Mock()
        with self.assertRaises(ValueError):
            ci_gate.hosted_lint({}, run=run)
        run.assert_not_called()

    def test_real_subprocess_output_classifier(self):
        cases = [
            ("Could not download dependency\nCould not GET https://repo.maven.apache.org/maven2/x\nReceived status code 429", True),
            ("Received status code 429", False),
            ("Could not GET https://other.example/maven2/x\nReceived status code 429", False),
            ("Could not GET https://repo.maven.apache.org/maven2/x\nReceived status code 500", False),
            ("lint error", False),
        ]
        for output, retry in cases:
            with self.subTest(output=output):
                rc, actual = ci_gate.run_lint_once([sys.executable, "-c", "import sys; print(sys.argv[1]); sys.exit(7)", output], ROOT)
                self.assertEqual((rc, actual), (7, retry))


class WorkflowGraphTests(unittest.TestCase):
    def block(self, text, job):
        return re.search(r"(?ms)^  " + re.escape(job) + r":\n(.*?)(?=^  [a-z][a-z0-9-]*:\s*$|\Z)", text).group(1)

    def test_required_fanout_waits_and_aggregate_rejects_skips(self):
        for name, jobs in (("fork-manager-ci.yml", ["manager-debug"]),
                           ("lints-check.yml", ["clang-format", "rustfmt", "clippy", "shellcheck", "check-crlf", "android-lint", "webui-contract"])):
            text = (ROOT / ".github/workflows" / name).read_text()
            self.assertIn("scripts/fork/ci_gate.py source", self.block(text, "source-contract"))
            self.assertIn("ci_inventory.py --github-api", self.block(text, "source-contract"))
            self.assertIn("actions: read", self.block(text, "source-contract"))
            for job in jobs:
                self.assertIn("needs: source-contract", self.block(text, job))
                self.assertIn("ci_gate.py checkout", self.block(text, job))
            aggregate = self.block(text, "qualification")
            self.assertIn("if: ${{ always() }}", aggregate)
            self.assertIn("needs: [" + ", ".join(["source-contract", *jobs]) + "]", aggregate)
            variables = re.findall(r"^          ([A-Z_]+): \$\{\{ needs\.[^.]+\.result \}\}$", aggregate, re.M)
            self.assertEqual(len(variables), len(jobs) + 1)
            match = re.search(r"(?ms)^        run: \|\n(.*)$", aggregate)
            cmd = "\n".join(line[10:] for line in match.group(1).splitlines()) if match else re.search(r"^        run: (.*)$", aggregate, re.M).group(1)
            env = dict(os.environ, **{k: "success" for k in variables})
            self.assertEqual(subprocess.run(["bash", "-c", cmd], env=env).returncode, 0)
            for key in variables:
                for outcome in ("failure", "skipped", "cancelled", ""):
                    self.assertNotEqual(subprocess.run(["bash", "-c", cmd], env=dict(env, **{key: outcome})).returncode, 0)

    def test_codeql_schedule_not_skipped_and_pr_gate_preserved(self):
        text = (ROOT / ".github/workflows/codeql.yml").read_text()
        pre = self.block(text, "pre_job")
        self.assertNotRegex(pre, r"(?m)^    if:")
        self.assertIn("if: github.event_name != 'schedule'", pre)
        self.assertIn("scripts/fork/ci_gate.py source", pre)
        analyze = self.block(text, "analyze")
        self.assertIn("needs.pre_job.result == 'success'", analyze)
        self.assertIn("github.event_name == 'schedule'", analyze)
        self.assertIn("github/codeql-action/analyze@v4", analyze)
        self.assertIn("ci_gate.py checkout", analyze)


if __name__ == "__main__":
    unittest.main()
