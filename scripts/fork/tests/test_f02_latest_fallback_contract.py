"""A newer author update ZIP cannot masquerade as the installed version."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[3]
P=ROOT/'manager/app/src/main/java/org/bakasu/bakasu'
class ReinstallLatestFallbackContract(unittest.TestCase):
    def test_exact_or_latest_candidate_can_be_selected(self):
        repo=(P/'data/module/ModuleRepository.kt').read_text()
        self.assertIn('it.versionCode >= module.versionCode',repo)
        vm=(P/'ui/viewmodel/ModuleViewModel.kt').read_text()
        self.assertIn('candidate.versionCode < module.versionCode',vm)
    def test_newer_zip_is_disclosed_before_install(self):
        ui=(P/'ui/screen/main/ModulePage.kt').read_text()
        self.assertIn('val latestFallback =',ui)
        self.assertIn('module_reinstall_latest_explanation',ui)
        for loc in ('values','values-pt-rBR'):
            strings=(ROOT/f'manager/app/src/main/res/{loc}/strings.xml').read_text()
            for key in ('module_reinstall_latest','module_reinstall_latest_explanation'):
                self.assertEqual(strings.count(f'name="{key}"'),1)
if __name__=='__main__':unittest.main()
