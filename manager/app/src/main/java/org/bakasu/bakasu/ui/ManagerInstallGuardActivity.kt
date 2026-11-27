package org.bakasu.bakasu.ui

import android.content.Intent
import android.os.Bundle
import android.os.Environment
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bakasu.bakasu.BuildConfig
import org.bakasu.bakasu.data.download.DownloadService
import org.bakasu.bakasu.data.kernel.KernelRepository
import org.bakasu.bakasu.data.update.ManagerApkIntegrity
import org.bakasu.bakasu.domain.model.ManagerCompatibilityRequirements
import org.bakasu.bakasu.domain.model.ManagerCompatibilityVerdict
import org.bakasu.bakasu.domain.model.evaluateManagerCompatibility
import org.koin.android.ext.android.inject

/** Explicit user action; revalidates the physical APK and kernel just before installation. */
class ManagerInstallGuardActivity : ComponentActivity() {
    private val kernels: KernelRepository by inject()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycleScope.launch {
            val result = runCatching {
                val expectedHash = intent.getStringExtra(DownloadService.EXTRA_EXPECTED_SHA256)
                    ?: error("Missing APK proof")
                val expectedBytes = intent.getLongExtra(DownloadService.EXTRA_EXPECTED_SIZE, -1)
                val code = intent.getIntExtra(DownloadService.EXTRA_MANAGER_EXPECTED_VERSION_CODE, -1)
                val managerUapi = intent.getIntExtra(DownloadService.EXTRA_MANAGER_UAPI, -1)
                val minKsu = intent.getIntExtra(DownloadService.EXTRA_MANAGER_KSU_MIN, -1)
                val expectedSigner = intent.getStringExtra(DownloadService.EXTRA_MANAGER_SIGNER) ?: error("Missing reviewed signer")
                val expectedAbi = intent.getStringExtra(DownloadService.EXTRA_MANAGER_SELECTED_ABI) ?: error("Missing selected ABI")
                val path = intent.getStringExtra(DownloadService.EXTRA_FILE_PATH)
                    ?: error("Missing downloaded APK")
                val downloadRoot = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS,
                ).canonicalFile
                val apk = File(path)
                check(apk.canonicalFile.parentFile == downloadRoot && !apk.isDirectory) {
                    "Unexpected downloaded APK location"
                }
                val requirements = ManagerCompatibilityRequirements(managerUapi, minKsu)
                val status = kernels.getStatus()
                check(
                    evaluateManagerCompatibility(
                        requirements,
                        status.isManager,
                        status.isRootAvailable,
                        status.kernelUAPIVersion,
                        status.ksuVersion,
                    ) == ManagerCompatibilityVerdict.COMPATIBLE,
                ) {
                    "Kernel or manager authorization changed"
                }
                // Keep the signed, verified APK outside mutable public Downloads
                // while Android's installer is resolving its content URI.
                val privateFile = withContext(Dispatchers.IO) {
                    // Never remove the current APK before Android finishes reading it.
                    // Reclaim only expired copies from earlier install attempts.
                    val expiry = System.currentTimeMillis() - 7L * 24 * 60 * 60 * 1000
                    cacheDir.listFiles()?.forEach { old ->
                        if (old.name.startsWith("fork-install-") && old.name.endsWith(".apk") &&
                            old.isFile && !java.nio.file.Files.isSymbolicLink(old.toPath()) &&
                            old.lastModified() < expiry
                        ) {
                            old.delete()
                        }
                    }
                    val dest = File.createTempFile("fork-install-", ".apk", cacheDir)
                    try {
                        apk.inputStream().use { input -> dest.outputStream().use { input.copyTo(it) } }
                        ManagerApkIntegrity.verify(this@ManagerInstallGuardActivity, dest, expectedHash, expectedBytes, code, expectedSigner, expectedAbi)
                        dest
                    } catch (e: Exception) {
                        dest.delete()
                        throw e
                    }
                }
                val uri = FileProvider.getUriForFile(
                    this@ManagerInstallGuardActivity,
                    "${BuildConfig.APPLICATION_ID}.fileprovider",
                    privateFile,
                )
                startActivity(
                    Intent(Intent.ACTION_VIEW).apply {
                        setDataAndType(uri, "application/vnd.android.package-archive")
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    },
                )
            }
            result.onFailure { failure ->
                Toast.makeText(
                    this@ManagerInstallGuardActivity,
                    "Fork manager update refused: ${failure.message ?: "invalid release"}",
                    Toast.LENGTH_LONG,
                ).show()
            }
            finish()
        }
    }
}
