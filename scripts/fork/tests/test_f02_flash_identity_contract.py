"""Reinstallation must reach the flash layer with immutable expected identity."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'manager/app/src/main/java/org/bakasu/bakasu'
class FlashIdentityContract(unittest.TestCase):
    def test_reinstall_route_is_separate_from_update(self):
        routes=(BASE/'ui/navigation/Routes.kt').read_text()
        self.assertIn('fun moduleReinstall(',routes)
        self.assertIn('reinstallModuleId = moduleId',routes)
        nav=(BASE/'ui/NavContainer.kt').read_text()
        self.assertIn('reinstallModuleId,',nav)
    def test_archive_id_digest_and_safe_entries(self):
        verifier=(BASE/'data/file/ReinstallArchiveVerifier.kt').read_text()
        for token in ('expectedModuleId','expectedSha256','expectedSize',
                      'actualSha == expectedSha256','ModuleArchiveIdentity.verify(bytes, expectedModuleId, expectedArchiveVersionCode)',
                      'entry.isUnixSymlink','copy.delete()'):
            self.assertIn(token,verifier)
        identity=(BASE/'data/file/ModuleArchiveIdentity.kt').read_text()
        self.assertIn('prop.getProperty("id") == expectedModuleId',identity)
        self.assertIn('prop.getProperty("versionCode")?.toIntOrNull() == expectedVersionCode',identity)
    def test_zip_bomb_constraints(self):
        verifier=(BASE/'data/file/ReinstallArchiveVerifier.kt').read_text()
        self.assertIn('names.size < 10000', verifier)
        self.assertIn('entry.size >= 0L', verifier)
        self.assertIn('totalUncompressed <= MAX_ZIP_BYTES * 4 - entry.size', verifier)
        self.assertIn('zip.getInputStream(entry).use', verifier)
        self.assertIn('setIgnoreLocalFileHeader(false)', verifier)
        self.assertIn('actualEntryBytes == entry.size', verifier)
    def test_flash_refreshes_and_freezes_archive(self):
        screen=(BASE/'ui/screen/Flash.kt').read_text()
        self.assertIn('refreshInstalledModules(manual = true, checkUpdates = false)',screen)
        self.assertIn('ReinstallArchiveVerifier.prepare(',screen)
        self.assertIn('preparedReinstall?.delete()',screen)
if __name__=='__main__':unittest.main()
