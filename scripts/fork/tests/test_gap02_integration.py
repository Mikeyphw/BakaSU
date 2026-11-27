"""Source integration contracts for GAP-02; executable policy probe is separate."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "manager/app/src/main/java/org/bakasu/bakasu"


class Gap02Integration(unittest.TestCase):
    def test_historical_candidate_freshly_revalidated(self):
        registry = (BASE / "data/module/registry/KernelSuRegistryRepository.kt").read_text()
        for token in ("client.loadCatalog()", "loaded.fromCache", "HistoricalZipPolicy.select(", "HistoricalZipPolicy.claimsAnchor(", "Semaphore(3)"):
            self.assertIn(token, registry)
        view = (BASE / "ui/viewmodel/ModuleViewModel.kt").read_text()
        self.assertIn("resolveModuleUpdate.historical(", view)
        self.assertIn("if (current == candidate) historical else ModuleUpdateVerification.Rejected", view)
        self.assertIn("installed.dirId == module.dirId", view)

    def test_archive_identity_reaches_flash(self):
        page = (BASE / "ui/screen/main/ModulePage.kt").read_text()
        self.assertIn("requireNotNull(reinstallModule.moduleReinstall).versionCode", page)
        flash = (BASE / "ui/screen/Flash.kt").read_text()
        self.assertEqual(flash.count("it.dirId == flashIt.reinstallDirId"), 2)
        self.assertIn("requireNotNull(flashIt.reinstallArchiveVersionCode)", flash)

    def test_release_metadata_digest_and_signer(self):
        repo = (BASE / "data/update/ManagerUpdateRepository.kt").read_text()
        self.assertIn('verifiedReleaseDocument(assets, releaseTag, "manager-compatibility.json")', repo)
        self.assertIn('verifiedReleaseDocument(assets, releaseTag, "f07-release-provenance.json")', repo)
        self.assertIn("response.bodySha256 != digest || response.bodySize != size", repo)
        apk = (BASE / "data/update/ManagerApkIntegrity.kt").read_text()
        self.assertIn("candidateCerts.single() == expectedSigner", apk)
        self.assertIn("ManagerReleaseProof.supportsArchiveAbi", apk)
        for path in ("data/download/DownloadService.kt", "ui/ManagerInstallGuardActivity.kt"):
            text = (BASE / path).read_text()
            self.assertIn("ManagerApkIntegrity.verify(", text)
            self.assertIn("expectedSigner", text)
            self.assertIn("expectedAbi", text)

    def test_probe_required_before_existing_build(self):
        workflow = (ROOT / ".github/workflows/fork-manager-ci.yml").read_text()
        self.assertLess(workflow.index("run: python3 -B ../scripts/fork/gap02_policy_probe.py"), workflow.index("./gradlew spotlessCheck"))
        self.assertIn("./gradlew :app:assembleDebug", workflow)
        self.assertIn('test "$SOURCE_RESULT" = success && test "$BUILD_RESULT" = success', workflow)
