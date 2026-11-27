package org.bakasu.bakasu.data.module.registry

import java.net.URI

/** A historical asset is eligible only through an already source-bound release roster. */
internal data class HistoricalZipRecord(
    val tag: String,
    val versionCode: Int,
    val url: String,
    val size: Long,
    val sha256: String,
    val immutable: Boolean,
)

internal object HistoricalZipPolicy {
    private val digest = Regex("[a-f0-9]{64}")
    private const val MAX_ZIP_SIZE = 1_073_741_824L

    private fun releasePath(url: String): List<String>? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        if (!uri.scheme.equals("https", true) || !uri.host.equals("github.com", true) ||
            uri.port !in listOf(-1, 443) || uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null
        ) return null
        val path = uri.rawPath?.removePrefix("/")?.split('/') ?: return null
        if (path.size != 6 || path[2] != "releases" || path[3] != "download") return null
        val decoded = path.map {
            runCatching { java.net.URLDecoder.decode(it.replace("+", "%2B"), "UTF-8") }.getOrNull() ?: return null
        }
        if (decoded.any { it.isBlank() || it == "." || it == ".." || '/' in it || '\\' in it }) return null
        return decoded.takeIf { it.last().endsWith(".zip", ignoreCase = true) }
    }

    private fun valid(record: HistoricalZipRecord): Boolean = record.immutable && record.tag.isNotBlank() &&
        record.versionCode >= 0 && record.size in 1..MAX_ZIP_SIZE && digest.matches(record.sha256) &&
        releasePath(record.url)?.get(4) == record.tag

    private fun equalUrl(left: String, right: String): Boolean {
        val a = runCatching { URI(left) }.getOrNull() ?: return false
        val b = runCatching { URI(right) }.getOrNull() ?: return false
        return a.scheme.equals("https", true) && b.scheme.equals("https", true) &&
            a.host.equals("github.com", true) && b.host.equals("github.com", true) &&
            a.port in listOf(-1, 443) && b.port in listOf(-1, 443) &&
            a.rawUserInfo == null && b.rawUserInfo == null && a.rawQuery == null && b.rawQuery == null &&
            a.rawFragment == null && b.rawFragment == null && a.rawPath == b.rawPath
    }

    fun claimsAnchor(offeredUrl: String, records: List<HistoricalZipRecord>): Boolean = records.any { equalUrl(it.url, offeredUrl) }

    fun anchor(offeredCode: Int, offeredUrl: String, records: List<HistoricalZipRecord>): HistoricalZipRecord? {
        val anchor = records.filter { equalUrl(it.url, offeredUrl) }.singleOrNull() ?: return null
        return anchor.takeIf { valid(it) && it.versionCode == offeredCode }
    }

    /** Never infer a version from a tag or filename, and never choose among duplicate version codes. */
    fun select(installedCode: Int, offeredCode: Int, offeredUrl: String, records: List<HistoricalZipRecord>): HistoricalZipRecord? {
        if (installedCode < 0 || offeredCode <= installedCode) return null
        val anchor = anchor(offeredCode, offeredUrl, records) ?: return null
        val selected = records.filter { it.versionCode == installedCode }.singleOrNull() ?: return null
        return selected.takeIf {
            valid(it) && !equalUrl(it.url, anchor.url) &&
                releasePath(it.url)?.take(2) == releasePath(anchor.url)?.take(2) &&
                records.count { candidate -> equalUrl(candidate.url, it.url) } == 1
        }
    }
}
