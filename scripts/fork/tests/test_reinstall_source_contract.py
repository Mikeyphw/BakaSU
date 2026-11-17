"""F02 static wiring and safety contracts. Compilation is a separate hosted CI gate.

These assertions intentionally test source integration, not runtime module safety.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]  # tests[0], fork[1], scripts[2], repo[3]


def src(path: str) -> str:
    return (ROOT / path).read_text(encoding='utf-8')


class ReinstallSourceContract(unittest.TestCase):
    def test_exact_version_candidate_separate_from_update(self):
        r = src('manager/app/src/main/java/org/bakasu/bakasu/data/module/ModuleRepository.kt')
        self.assertIn('candidate?.takeIf { it.versionCode > module.versionCode }', r)
        self.assertIn('it.versionCode >= module.versionCode', r)
        self.assertIn('isSecureReinstallZipUrl(it.zipUrl)', r)
        self.assertIn('uri.scheme.equals("https", ignoreCase = true)', r)
        self.assertIn('cached?.moduleUpdate ?: cached?.moduleReinstall', r)
        self.assertIn('metadata?.takeIf { it.versionCode > currentVersionCode }', r)

    def test_verification_guard_and_no_pending_remove(self):
        v = src('manager/app/src/main/java/org/bakasu/bakasu/ui/viewmodel/ModuleViewModel.kt')
        self.assertIn('suspend fun resolveReinstall(', v)
        self.assertIn('resolveModuleUpdate(module.id, module.updateJson, candidate.zipUrl, candidate.versionCode)', v)
        self.assertIn('resolveModuleUpdate.isCurrent(verification)', v)
        self.assertIn('!installed.remove', v)
        self.assertIn('!installed.update', v)
        self.assertIn('installed.moduleReinstall == module.moduleReinstall', v)

    def test_confirmed_flash_reuses_verified_pipeline(self):
        p = src('manager/app/src/main/java/org/bakasu/bakasu/ui/screen/main/ModulePage.kt')
        self.assertIn('onReinstall = {', p)
        self.assertIn('reinstall = true', p)
        self.assertIn('viewModel.resolveReinstall(module)', p)
        self.assertIn('viewModel.isReinstallCurrent(module, registry)', p)
        self.assertIn('module_reinstall_unverified', p)
        self.assertIn('if (confirmResult != ConfirmResult.Confirmed)', p)
        self.assertIn('expected = registry?.expected', p)
        self.assertIn('onUpdateModule(', p)
        self.assertIn('module.takeIf { reinstall }', p)
        self.assertIn('reinstallModuleId', (ROOT/'manager/app/src/main/java/org/bakasu/bakasu/ui/screen/Flash.kt').read_text())
        self.assertIn('reinstallUrl.isNotEmpty() && !module.remove && !module.update', p)

    def test_preview_and_localization(self):
        p = src('manager/app/src/main/java/org/bakasu/bakasu/ui/screen/main/ModulePage.kt')
        self.assertIn('onReinstall: (InstalledModule) -> Unit', p)
        for language in ('values', 'values-pt-rBR'):
            v = src(f'manager/app/src/main/res/{language}/strings.xml')
            for key in ('module_reinstall', 'module_reinstall_confirm', 'module_reinstall_verified', 'module_reinstall_unverified'):
                self.assertEqual(v.count(f'name="{key}"'), 1, (language, key))


if __name__ == '__main__':
    unittest.main()
