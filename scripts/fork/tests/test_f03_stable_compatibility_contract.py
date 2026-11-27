"""Both fork update channels must use candidate-specific kernel compatibility checks."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[3]
REPO=(ROOT/'manager/app/src/main/java/org/bakasu/bakasu/data/update/ManagerUpdateRepository.kt')
HOME=(ROOT/'manager/app/src/main/java/org/bakasu/bakasu/ui/screen/main/HomePage.kt')
class StableCompatibilitySourceContract(unittest.TestCase):
    def test_stable_fetches_candidate_specific_compatibility(self):
        text=REPO.read_text()
        stable=text.split('suspend fun checkStableUpdate()',1)[1].split('suspend fun checkBetaUpdate()',1)[0]
        self.assertIn('resolvePublishedCompatibility(assets, candidate, releaseTag, "stable")',stable)
        self.assertIn('.copy(compatibilityRequirements = requirements)',stable)
    def test_both_channels_block_incompatible_and_unknown(self):
        page=HOME.read_text()
        part=page.split('private fun ManagerUpdateCardContent',1)[1]
        self.assertNotIn('ManagerCompatibilityVerdict.COMPATIBLE\n    } else {',part)
        self.assertIn('if (compatibility != ManagerCompatibilityVerdict.COMPATIBLE)',part)
        self.assertIn('val currentVerdict = freshStatus?.let',part)
        self.assertIn('if (currentVerdict == ManagerCompatibilityVerdict.COMPATIBLE)',part)
if __name__=='__main__':unittest.main()
