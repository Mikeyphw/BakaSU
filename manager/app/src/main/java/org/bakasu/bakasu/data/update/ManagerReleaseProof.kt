package org.bakasu.bakasu.data.update

import org.bakasu.bakasu.domain.model.ManagerCompatibilityRequirements

internal data class ReleaseApkIdentity(val fileName: String, val versionCode: Int, val abi: String, val sha256: String, val size: Long)
internal data class CompatibilityRow(val fileName: String, val versionCode: Int, val abi: String, val managerUapi: Int, val minimumKernelSuVersion: Int)
internal data class ProvenanceRow(val fileName: String, val sha256: String, val size: Long)

/** Exact published asset, reviewed capability metadata and installed signer must agree. */
internal object ManagerReleaseProof {
    private val hash = Regex("[a-f0-9]{64}")
    private val commit = Regex("[a-f0-9]{40}")
    private val tag = Regex("f07-v[0-9][A-Za-z0-9._-]{0,75}")
    private val filename = Regex("BakaSU_[A-Za-z0-9._+-]+_[0-9]+-(arm64-v8a|armeabi-v7a|x86_64|universal)-release\\.apk")
    private val nativeAbis = setOf("arm64-v8a", "armeabi-v7a", "x86_64", "riscv64")
    const val MAX_APK = 1_073_741_824L

    fun validDigest(value: String): Boolean = hash.matches(value)
    fun validSource(value: String): Boolean = commit.matches(value)
    fun validTag(value: String): Boolean = tag.matches(value)

    fun assetUrl(releaseTag: String, name: String): String? {
        if (!validTag(releaseTag) || !(filename.matches(name) || name in setOf("manager-compatibility.json", "f07-release-provenance.json"))) return null
        return "https://github.com/Mikeyphw/BakaSU/releases/download/$releaseTag/$name"
    }

    fun requirements(
        identity: ReleaseApkIdentity,
        compatibility: List<CompatibilityRow>,
        provenance: List<ProvenanceRow>,
        releaseSigner: String,
        installedSigner: String?,
    ): ManagerCompatibilityRequirements? {
        if (!validDigest(releaseSigner) || releaseSigner != installedSigner ||
            !validDigest(identity.sha256) || identity.size !in 100_001L..MAX_APK ||
            identity.versionCode <= 0 || !filename.matches(identity.fileName) ||
            compatibility.size !in 1..10 || provenance.size != compatibility.size
        ) return null
        if (compatibility.map { it.fileName }.toSet().size != compatibility.size ||
            provenance.map { it.fileName }.toSet().size != provenance.size ||
            compatibility.map { it.fileName }.toSet() != provenance.map { it.fileName }.toSet() ||
            compatibility.map { it.abi }.toSet().size != compatibility.size
        ) return null
        if (compatibility.any {
                !filename.matches(it.fileName) || it.versionCode != identity.versionCode ||
                    it.managerUapi <= 0 || it.minimumKernelSuVersion <= 0 ||
                    !it.fileName.endsWith("_${it.versionCode}-${it.abi}-release.apk") ||
                    (it.abi != "universal" && it.abi !in nativeAbis)
            } || provenance.any { !validDigest(it.sha256) || it.size !in 100_001L..MAX_APK }
        ) return null
        val row = compatibility.singleOrNull { it.fileName == identity.fileName && it.versionCode == identity.versionCode && it.abi == identity.abi } ?: return null
        val asset = provenance.singleOrNull { it.fileName == identity.fileName } ?: return null
        if (asset.sha256 != identity.sha256 || asset.size != identity.size) return null
        return ManagerCompatibilityRequirements(row.managerUapi, row.minimumKernelSuVersion, releaseSigner, identity.abi)
    }

    fun supportsArchiveAbi(expected: String, supported: List<String>, archiveAbis: Set<String>): Boolean {
        if (archiveAbis.isEmpty() || archiveAbis.any { it !in nativeAbis }) return false
        return if (expected == "universal") archiveAbis.any { it in supported } else expected in supported && archiveAbis == setOf(expected)
    }
}
