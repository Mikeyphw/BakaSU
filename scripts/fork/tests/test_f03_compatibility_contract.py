"""F03 source contracts: fork-only beta, build-specific metadata, fail-closed UI."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding='utf-8')


class BetaCompatibilityContracts(unittest.TestCase):
    def test_fork_only_published_beta(self):
        repo = read('manager/app/src/main/java/org/bakasu/bakasu/data/update/ManagerUpdateRepository.kt')
        self.assertIn('const val REPOSITORY = "Mikeyphw/BakaSU"', repo)
        self.assertIn('!release.optBoolean("prerelease")', repo)
        self.assertIn('https://github.com/$REPOSITORY/releases/download/', repo)
        self.assertIn('manager-compatibility.json', repo)
        self.assertIn('.copy(compatibilityRequirements = requirements)', repo)
        self.assertNotIn('nightly.link/$REPOSITORY/actions/runs/$runId', repo)

    def test_build_specific_manifest(self):
        m = read('manager/app/src/main/java/org/bakasu/bakasu/data/update/ManagerCompatibilityManifest.kt')
        for token in ('schemaVersion', 'versionCode', 'fileName', 'abi', 'matching.size != 1', 'managerUapi', 'minimumKernelSuVersion'):
            self.assertIn(token, m)

    def test_compatibility_fail_closed(self):
        p = read('manager/app/src/main/java/org/bakasu/bakasu/domain/model/ManagerCompatibilityPolicy.kt')
        for token in ('candidate == null', '!isManager || !rootAvailable',
                      'kernelUapiVersion != candidate.managerUapi',
                      'kernelSuVersion < candidate.minimumKernelSuVersion',
                      'ManagerCompatibilityVerdict.UNKNOWN'):
            self.assertIn(token, p)

    def test_ui_no_incompatible_download(self):
        page = read('manager/app/src/main/java/org/bakasu/bakasu/ui/screen/main/HomePage.kt')
        self.assertIn('if (compatibility != ManagerCompatibilityVerdict.COMPATIBLE)', page)
        self.assertIn('R.string.manager_beta_unverified', page)
        self.assertIn('R.string.manager_beta_incompatible', page)
        self.assertIn('val freshStatus = runCatching { getKernelStatus() }.getOrNull()', page)
        self.assertIn('if (currentVerdict == ManagerCompatibilityVerdict.COMPATIBLE)', page)
        self.assertIn('R.string.manager_beta_changed', page)
        for locale in ('values', 'values-pt-rBR'):
            s = read(f'manager/app/src/main/res/{locale}/strings.xml')
            for key in ('manager_beta_unverified','manager_beta_incompatible','manager_beta_changed'):
                self.assertEqual(s.count(f'name="{key}"'), 1)

if __name__ == '__main__':
    unittest.main()
