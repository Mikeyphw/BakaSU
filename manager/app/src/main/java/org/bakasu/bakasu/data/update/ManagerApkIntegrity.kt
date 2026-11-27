package org.bakasu.bakasu.data.update

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.util.zip.ZipFile
import org.bakasu.bakasu.BuildConfig

/** Fail-closed APK byte, package, version and installed-certificate continuity. */
object ManagerApkIntegrity {
    private val sha256Regex = Regex("[a-f0-9]{64}")

    fun verify(
        context: Context,
        apk: File,
        expectedSha256: String,
        expectedBytes: Long,
        expectedVersionCode: Int,
        expectedSigner: String,
        expectedAbi: String,
    ) {
        require(
            sha256Regex.matches(expectedSha256) && expectedBytes > 100_000L &&
                expectedVersionCode > 0 && sha256Regex.matches(expectedSigner),
        ) { "Incomplete signed release metadata" }
        require(!apk.isSymbolicLink() && apk.isFile && apk.length() == expectedBytes) {
            "APK size or file safety mismatch"
        }
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(apk).use { stream ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val count = stream.read(buf)
                if (count < 0) break
                digest.update(buf, 0, count)
            }
        }
        val hash = digest.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
        require(hash == expectedSha256) { "APK SHA-256 does not match the fork release" }

        @Suppress("DEPRECATION")
        val flag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            PackageManager.GET_SIGNATURES
        }
        val pm = context.packageManager

        @Suppress("DEPRECATION")
        val candidate = pm.getPackageArchiveInfo(apk.absolutePath, flag)
            ?: throw SecurityException("APK package metadata unavailable")

        @Suppress("DEPRECATION")
        val installed = pm.getPackageInfo(BuildConfig.APPLICATION_ID, flag)
        require(
            candidate.packageName == BuildConfig.APPLICATION_ID &&
                candidate.versionCodeLong() == expectedVersionCode.toLong(),
        ) {
            "APK package identity or version mismatch"
        }
        require(expectedVersionCode.toLong() > installed.versionCodeLong()) {
            "Stale fork manager APK or already installed version"
        }
        val candidateCerts = candidate.certificatesSha256()
        val installedCerts = installed.certificatesSha256()
        require(
            candidateCerts.size == 1 && installedCerts.size == 1 &&
                candidateCerts.single() == installedCerts.single() && candidateCerts.single() == expectedSigner,
        ) {
            "APK signer does not match the installed fork"
        }
        val archiveAbis = ZipFile(apk).use { zip ->
            zip.entries().asSequence().map { it.name.split('/') }
                .filter { it.size == 3 && it[0] == "lib" && it[2].endsWith(".so") }
                .map { it[1] }.toSet()
        }
        require(ManagerReleaseProof.supportsArchiveAbi(expectedAbi, Build.SUPPORTED_ABIS.toList(), archiveAbis)) {
            "APK native ABI differs from selected release or device"
        }
    }

    @Suppress("DEPRECATION")
    fun installedCertificate(context: Context): String? = runCatching {
        val flag = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        context.packageManager.getPackageInfo(BuildConfig.APPLICATION_ID, flag).certificatesSha256().singleOrNull()
    }.getOrNull()

    private fun File.isSymbolicLink(): Boolean = runCatching {
        java.nio.file.Files.isSymbolicLink(toPath())
    }.getOrDefault(true)

    @Suppress("DEPRECATION")
    private fun android.content.pm.PackageInfo.versionCodeLong(): Long = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        longVersionCode
    } else {
        versionCode.toLong()
    }

    @Suppress("DEPRECATION")
    private fun android.content.pm.PackageInfo.certificatesSha256(): List<String> {
        val certs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            signingInfo?.apkContentsSigners?.toList().orEmpty()
        } else {
            signatures?.toList().orEmpty()
        }
        return certs.map { signature ->
            MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
                .joinToString("") { "%02x".format(it.toInt() and 255) }
        }
    }
}
