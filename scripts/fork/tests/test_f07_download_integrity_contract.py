"""Check fork APK digest/cert/version checks cannot be removed silently."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[3]
P=ROOT/'manager/app/src/main/java/org/bakasu/bakasu'
class ManagerApkDownloadIntegrityContract(unittest.TestCase):
    def test_github_asset_sha256_is_bound_to_candidate(self):
        src=(P/'data/update/ManagerUpdateRepository.kt').read_text()
        self.assertIn('sha256:[a-f0-9]{64}',src)
        self.assertIn('expectedApkSha256 = expectedSha256',src)
        self.assertIn('expectedApkSizeBytes = expectedSizeBytes',src)
    def test_download_requires_proof_and_checks_apk(self):
        repository=(P/'data/download/DownloadRepository.kt').read_text()
        service=(P/'data/download/DownloadService.kt').read_text()
        self.assertIn('Unsigned or incomplete fork release evidence',repository)
        self.assertIn('ManagerApkIntegrity.verify(',service)
        self.assertIn('ManagerInstallGuardActivity::class.java',service)
        self.assertIn('expectedBytes > 1_073_741_824L',service)
    def test_exact_source_and_bounded_stream(self):
        service=(P/'data/download/DownloadService.kt').read_text()
        for phrase in ('https://github.com/Mikeyphw/BakaSU/releases/download/f07-v',
                       'downloadUrlToTarget(id, url, target, expectedBytes)',
                       'expectedBytes != null && copied > expectedBytes',
                       'expectedBytes != null && copied != expectedBytes'):
            self.assertIn(phrase, service)
    def test_installed_certificate_package_and_version_verified(self):
        verifier=(P/'data/update/ManagerApkIntegrity.kt').read_text()
        for k in ('candidate.packageName == BuildConfig.APPLICATION_ID',
                  'candidate.versionCodeLong() == expectedVersionCode.toLong()',
                  'candidateCerts.single() == installedCerts.single()',
                  'expectedVersionCode.toLong() > installed.versionCodeLong()',
                  'hash == expectedSha256'):
            self.assertIn(k,verifier)
    def test_final_kernel_and_private_apk_gate(self):
        guard=(P/'ui/ManagerInstallGuardActivity.kt').read_text()
        self.assertIn('kernels.getStatus()',guard)
        self.assertIn('ManagerCompatibilityVerdict.COMPATIBLE',guard)
        self.assertIn('ManagerApkIntegrity.verify(',guard)
        self.assertIn('File.createTempFile("fork-install-", ".apk", cacheDir)',guard)
if __name__=='__main__':unittest.main()
