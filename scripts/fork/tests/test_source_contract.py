"""Pure stdlib contract negative tests; no source mutations."""
from pathlib import Path
import importlib.util
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "source_contract.py"
spec = importlib.util.spec_from_file_location("source_contract", MODULE)
contract = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(contract)


class ContractTests(unittest.TestCase):
    def test_required_inventory_is_nonempty(self):
        self.assertGreaterEqual(len(contract.REQUIRED), 6)

    def test_empty_tree_refused(self):
        with tempfile.TemporaryDirectory() as d:
            problems = contract.check_tree(Path(d))
            self.assertEqual(len(problems), len(contract.REQUIRED))
            self.assertTrue(all(p.startswith("MISSING_FILE ") for p in problems))

    def test_missing_token_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for relative, tokens in contract.REQUIRED.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("\n".join(tokens), encoding="utf-8")
            self.assertEqual(contract.check_tree(root), [])
            first = next(iter(contract.REQUIRED))
            (root / first).write_text("unrelated content", encoding="utf-8")
            self.assertTrue(any("MISSING_CONTRACT" in p for p in contract.check_tree(root)))


    def test_secure_reinstall_contract_replaces_legacy_callback(self):
        path = "manager/app/src/main/java/org/bakasu/bakasu/ui/screen/main/ModulePage.kt"
        expected = contract.REQUIRED[path]
        self.assertNotIn("onUpdateModule(uri)", expected)
        for token in ("onUpdateModule(", "module.takeIf { reinstall }",
                      "Route.Flash.moduleReinstall(", "registry?.expected?.sha256",
                      "registry?.expected?.size"):
            self.assertIn(token, expected)
        flash = contract.REQUIRED[
            "manager/app/src/main/java/org/bakasu/bakasu/ui/screen/Flash.kt"
        ]
        self.assertIn("ReinstallArchiveVerifier.prepare(", flash)
        self.assertIn("reinstallModuleId", flash)
        self.assertIn("reinstallWasEnabled", flash)

    def test_unverified_flash_seam_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for relative, tokens in contract.REQUIRED.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("\n".join(tokens), encoding="utf-8")
            self.assertEqual(contract.check_tree(root), [])
            flash_path = root / "manager/app/src/main/java/org/bakasu/bakasu/ui/screen/Flash.kt"
            flash_path.write_text("generic unverified flash callback", encoding="utf-8")
            self.assertTrue(any(
                item.startswith("MISSING_CONTRACT ") and "Flash.kt" in item
                for item in contract.check_tree(root)
            ))


if __name__ == "__main__":
    unittest.main()
