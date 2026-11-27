package org.bakasu.bakasu.data.update

import android.app.Application
import android.os.Build
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bakasu.bakasu.BuildConfig
import org.bakasu.bakasu.data.module.registry.RegistryUrls
import org.bakasu.bakasu.data.network.NetworkRequestRepository
import org.bakasu.bakasu.domain.model.DocumentPolicy
import org.bakasu.bakasu.domain.model.ManagerApkSource
import org.bakasu.bakasu.domain.model.ManagerCompatibilityRequirements
import org.bakasu.bakasu.domain.model.ManagerUpdateChannel
import org.bakasu.bakasu.domain.model.ManagerUpdateInfo
import org.json.JSONArray
import org.json.JSONObject

class ManagerUpdateRepository(
    private val networkRequestRepository: NetworkRequestRepository,
    private val application: Application,
) {
    private companion object {
        const val UPDATE_CALL_TIMEOUT_SECONDS = 8L
        const val TAG = "ManagerUpdateRepository"
        const val REPOSITORY = "Mikeyphw/BakaSU"
        const val WORKFLOW_FILE = "build-manager.yml"
        const val BRANCH = "main"
        const val RELEASE_ARTIFACT = "Manager-release"
        val GITHUB_HEADERS = mapOf("Accept" to "application/vnd.github+json")

        // sync with build.gradle.kts
        const val CI_MANAGER_VERSION_CODE_OFFSET = 30000 + 700
        const val SHORT_SHA_LENGTH = 7
        const val UNIVERSAL_ABI = "universal"
    }

    private val managerApkPattern = Regex(
        "^BakaSU_(.+)_(\\d+)-(arm64-v8a|armeabi-v7a|x86_64|universal)-release\\.apk$",
    )
    private val commitCountLinkPattern = Regex("""[?&]page=(\d+)>; rel="last"""")

    suspend fun checkStableUpdate(): ManagerUpdateInfo? = withContext(Dispatchers.IO) {
        val supportedAbis = Build.SUPPORTED_ABIS.toList()
        val release = requestJson("https://api.github.com/repos/$REPOSITORY/releases/latest")
            ?: return@withContext null
        if (!release.optString("tag_name").startsWith("f07-v") || release.optBoolean("draft") ||
            release.optBoolean("prerelease")
        ) {
            return@withContext null
        }
        val releaseTag = release.optString("tag_name")
        if (!ManagerReleaseProof.validTag(releaseTag)) return@withContext null
        val changelog = release.optString("body")
        val assets = release.optJSONArray("assets") ?: return@withContext null
        val candidates = mutableListOf<ManagerApkCandidate>()

        for (index in 0 until assets.length()) {
            val asset = assets.optJSONObject(index) ?: continue
            val parsed = parseApkName(asset.optString("name")) ?: continue
            val downloadUrl = asset.optString("browser_download_url")
            if (downloadUrl != ManagerReleaseProof.assetUrl(releaseTag, parsed.fileName)) continue

            candidates += ManagerApkCandidate(
                versionName = parsed.versionName,
                versionCode = parsed.versionCode,
                abi = parsed.abi,
                fileName = parsed.fileName,
                source = ManagerApkSource.DirectApk(downloadUrl),
                expectedSha256 = releaseSha256(asset),
                expectedSizeBytes = asset.optLong("size", -1L),
            )
        }

        val candidate = selectCandidate(candidates, supportedAbis) ?: return@withContext null
        val requirements = resolvePublishedCompatibility(assets, candidate, releaseTag, "stable")
        return@withContext candidate.toUpdateInfo(ManagerUpdateChannel.STABLE, changelog)
            .copy(compatibilityRequirements = requirements)
    }

    // Only published APKs from this fork are candidates. An upstream workflow
    // artifact is NEVER a fork update. Missing compatibility metadata is
    // rendered as UNKNOWN by the Home screen and cannot be installed as beta.
    suspend fun checkBetaUpdate(): ManagerUpdateInfo? = withContext(Dispatchers.IO) {
        val supportedAbis = Build.SUPPORTED_ABIS.toList()
        val releases = requestJsonArray("https://api.github.com/repos/$REPOSITORY/releases?per_page=20")
            ?: return@withContext null
        for (releaseIndex in 0 until releases.length()) {
            val release = releases.optJSONObject(releaseIndex) ?: continue
            if (!release.optBoolean("prerelease") || release.optBoolean("draft") ||
                !release.optString("tag_name").startsWith("f07-v")
            ) {
                continue
            }
            val releaseTag = release.optString("tag_name")
            if (!ManagerReleaseProof.validTag(releaseTag)) continue
            val assets = release.optJSONArray("assets") ?: continue
            val candidates = mutableListOf<ManagerApkCandidate>()
            for (index in 0 until assets.length()) {
                val asset = assets.optJSONObject(index) ?: continue
                val parsed = parseApkName(asset.optString("name")) ?: continue
                val url = asset.optString("browser_download_url")
                if (url != ManagerReleaseProof.assetUrl(releaseTag, parsed.fileName)) continue
                candidates += ManagerApkCandidate(
                    versionName = parsed.versionName,
                    versionCode = parsed.versionCode,
                    abi = parsed.abi,
                    fileName = parsed.fileName,
                    source = ManagerApkSource.DirectApk(url),
                    expectedSha256 = releaseSha256(asset),
                    expectedSizeBytes = asset.optLong("size", -1L),
                )
            }
            val candidate = selectCandidate(candidates, supportedAbis) ?: continue
            val requirements = resolvePublishedCompatibility(assets, candidate, releaseTag, "beta")
            return@withContext candidate.toUpdateInfo(
                ManagerUpdateChannel.BETA,
                release.optString("body"),
            ).copy(compatibilityRequirements = requirements)
        }
        null
    }

    private suspend fun resolvePublishedCompatibility(
        assets: JSONArray,
        candidate: ManagerApkCandidate,
        releaseTag: String,
        channel: String,
    ): ManagerCompatibilityRequirements? {
        val digest = candidate.expectedSha256 ?: return null
        val installedSigner = ManagerApkIntegrity.installedCertificate(application) ?: return null
        val manifest = verifiedReleaseDocument(assets, releaseTag, "manager-compatibility.json") ?: return null
        val provenance = verifiedReleaseDocument(assets, releaseTag, "f07-release-provenance.json") ?: return null
        return parseManagerCompatibilityManifest(
            manifest,
            provenance,
            ReleaseApkIdentity(candidate.fileName, candidate.versionCode, candidate.abi, digest, candidate.expectedSizeBytes),
            releaseTag,
            channel,
            installedSigner,
        )
    }

    private suspend fun verifiedReleaseDocument(assets: JSONArray, releaseTag: String, name: String): JSONObject? {
        val asset = (0 until assets.length()).mapNotNull { assets.optJSONObject(it) }.singleOrNull { it.optString("name") == name }
            ?: return null
        val expectedUrl = ManagerReleaseProof.assetUrl(releaseTag, name) ?: return null
        if (asset.optString("browser_download_url") != expectedUrl) return null
        val digest = releaseSha256(asset) ?: return null
        val size = asset.optLong("size", -1)
        if (size !in 1L..1_048_576L) return null
        val response = networkRequestRepository.request(
            expectedUrl,
            forceNetwork = true,
            callTimeoutSeconds = UPDATE_CALL_TIMEOUT_SECONDS,
            maxResponseBytes = size,
            documentPolicy = DocumentPolicy.PublicHttps(),
        ).getOrNull() ?: return null
        if (response.bodySha256 != digest || response.bodySize != size || !RegistryUrls.isAllowedDownloadHop(response.url)) return null
        return runCatching { JSONObject(response.body ?: return null) }.getOrNull()
    }

    private suspend fun requestJsonArray(url: String): JSONArray? = networkRequestRepository
        .request(
            url = url,
            headers = GITHUB_HEADERS,
            forceNetwork = true,
            callTimeoutSeconds = UPDATE_CALL_TIMEOUT_SECONDS,
            maxResponseBytes = 4L * 1024 * 1024,
            documentPolicy = DocumentPolicy.SameOrigin("https://api.github.com/"),
        )
        .onFailure { Log.w(TAG, "Fork releases request failed", it) }
        .mapCatching { JSONArray(requireNotNull(it.body)) }
        .getOrNull()

    fun findNightlyApkEntry(
        entries: List<ZipEntryMetadata>,
        expectedVersionCode: Int,
        preferredAbi: String,
    ): ZipEntryMetadata? {
        val candidates = entries.mapNotNull { entry ->
            val parsed = parseApkName(entry.name.substringAfterLast('/')) ?: return@mapNotNull null
            if (parsed.versionCode == expectedVersionCode) entry to parsed else null
        }

        candidates.firstOrNull { (_, parsed) -> parsed.abi == preferredAbi }
            ?.first
            ?.let { return it }
        return candidates.firstOrNull { (_, parsed) -> parsed.abi == UNIVERSAL_ABI }?.first
    }

    private suspend fun requestJson(url: String): JSONObject? = networkRequestRepository
        .request(
            url = url,
            headers = GITHUB_HEADERS,
            forceNetwork = true,
            callTimeoutSeconds = UPDATE_CALL_TIMEOUT_SECONDS,
            maxResponseBytes = 4L * 1024 * 1024,
            documentPolicy = DocumentPolicy.SameOrigin("https://api.github.com/"),
        )
        .onFailure { Log.w(TAG, "GitHub update request failed", it) }
        .mapCatching { JSONObject(requireNotNull(it.body)) }
        .getOrNull()

    private suspend fun requestCommitCount(commitSha: String): Int? {
        val url = "https://api.github.com/repos/$REPOSITORY/commits?sha=$commitSha&per_page=1"
        val response = networkRequestRepository.request(
            url = url,
            headers = GITHUB_HEADERS,
            forceNetwork = true,
            callTimeoutSeconds = UPDATE_CALL_TIMEOUT_SECONDS,
        ).getOrElse {
            Log.w(TAG, "GitHub commit history request failed", it)
            return null
        }
        return parseCommitCount(response.header("Link")) ?: 1
    }

    internal fun parseCommitCount(linkHeader: String?): Int? = commitCountLinkPattern.find(linkHeader.orEmpty())
        ?.groupValues
        ?.getOrNull(1)
        ?.toIntOrNull()

    private fun parseApkName(fileName: String): ParsedApkName? {
        val match = managerApkPattern.matchEntire(fileName) ?: return null
        val versionCode = match.groupValues[2].toIntOrNull() ?: return null
        return ParsedApkName(
            versionName = match.groupValues[1],
            versionCode = versionCode,
            abi = match.groupValues[3],
            fileName = fileName,
        )
    }

    private fun releaseSha256(asset: JSONObject): String? = asset.optString("digest")
        .takeIf { it.matches(Regex("sha256:[a-f0-9]{64}")) }
        ?.removePrefix("sha256:")

    private fun selectCandidate(
        candidates: List<ManagerApkCandidate>,
        supportedAbis: List<String>,
    ): ManagerApkCandidate? {
        val latestVersionCode = candidates.maxOfOrNull { it.versionCode } ?: return null
        if (latestVersionCode <= BuildConfig.VERSION_CODE) return null

        val latestCandidates = candidates.filter { it.versionCode == latestVersionCode }
        if (latestCandidates.map { it.fileName }.toSet().size != latestCandidates.size ||
            latestCandidates.map { it.abi }.toSet().size != latestCandidates.size
        ) return null
        supportedAbis.forEach { abi ->
            latestCandidates.firstOrNull { it.abi == abi }?.let { return it }
        }
        return latestCandidates.firstOrNull { it.abi == "universal" }
    }

    private data class ParsedApkName(
        val versionName: String,
        val versionCode: Int,
        val abi: String,
        val fileName: String,
    )

    private data class ManagerApkCandidate(
        val versionName: String,
        val versionCode: Int,
        val abi: String,
        val fileName: String,
        val source: ManagerApkSource,
        val expectedSha256: String?,
        val expectedSizeBytes: Long,
    ) {
        fun toUpdateInfo(
            channel: ManagerUpdateChannel,
            changelog: String = "",
        ) = ManagerUpdateInfo(
            channel = channel,
            versionCode = versionCode,
            versionName = versionName,
            abi = abi,
            fileName = fileName,
            source = source,
            changelog = changelog,
            expectedApkSha256 = expectedSha256,
            expectedApkSizeBytes = expectedSizeBytes.takeIf { it > 100_000L },
        )
    }
}
