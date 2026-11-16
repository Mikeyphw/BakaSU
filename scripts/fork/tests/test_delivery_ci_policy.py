"""Source and trigger checks for the committed Devtool required-CI policy."""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / "config/delivery-required-ci.json"
BASELINE = ROOT / ".github/workflows/fork-manager-ci.yml"
LINT = ROOT / ".github/workflows/lints-check.yml"


class CommittedRequiredCIContracts(unittest.TestCase):
    def test_policy_schema_and_verified_workflow_identities(self):
        raw = json.loads(POLICY.read_text(encoding="utf-8"))
        self.assertEqual(set(raw), {"schema_version", "repository", "base_branch",
                                    "event", "release_qualification", "required_workflows"})
        self.assertEqual(raw["schema_version"], 1)
        self.assertEqual(raw["repository"], "Mikeyphw/BakaSU")
        self.assertEqual(raw["base_branch"], "main")
        self.assertEqual(raw["event"], "pull_request")
        self.assertEqual(raw["release_qualification"], "separate")
        self.assertEqual(raw["required_workflows"], [
            {"name": "Fork Manager Baseline Qualification", "workflow_id": 420307178},
            {"name": "Lints Check", "workflow_id": 420303004},
        ])
        self.assertEqual(len({x["workflow_id"] for x in raw["required_workflows"]}), 2)

    def test_required_workflows_are_real_and_unconditional_on_pr(self):
        for filename, name in ((BASELINE, "Fork Manager Baseline Qualification"),
                               (LINT, "Lints Check")):
            text = filename.read_text(encoding="utf-8")
            self.assertIn("name: " + name + "\n", text)
            self.assertIn("on:\n", text)
            self.assertRegex(text, r"(?m)^  pull_request:\s*$")
            match = re.search(r"(?ms)^  pull_request:\n(?P<body>.*?)(?=^  [A-Za-z_-][A-Za-z0-9_-]*:|\Z)", text)
            self.assertIsNotNone(match)
            block = match.group("body")
            self.assertNotRegex(block, r"(?m)^    paths(?:-ignore)?:")
            self.assertNotRegex(block, r"(?m)^    types:")
        baseline = BASELINE.read_text(encoding="utf-8")
        self.assertIn("./gradlew :app:assembleDebug", baseline)
        self.assertIn("./gradlew spotlessCheck", baseline)
        self.assertIn("test_*.py", baseline)
        self.assertIn("git diff --check", baseline)

    def test_not_mislabelled_as_release_or_device_qualified(self):
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        self.assertNotIn("CodeQL", [x["name"] for x in policy["required_workflows"]])
        self.assertNotIn("release_qualified", policy)
        self.assertNotIn("device_qualified", policy)

if __name__ == "__main__":
    unittest.main()
