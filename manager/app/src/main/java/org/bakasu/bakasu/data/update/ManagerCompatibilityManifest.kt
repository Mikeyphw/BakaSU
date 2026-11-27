package org.bakasu.bakasu.data.update

import org.bakasu.bakasu.domain.model.ManagerCompatibilityRequirements
import org.json.JSONObject

/** Both documents must already have passed their exact GitHub asset digest checks. */
internal fun parseManagerCompatibilityManifest(
    manifest: JSONObject,
    provenance: JSONObject,
    identity: ReleaseApkIdentity,
    releaseTag: String,
    channel: String,
    installedSigner: String?,
): ManagerCompatibilityRequirements? {
    val runId = provenance.opt("f06RunId")
    if (runId !is Int && runId !is Long) return null
    if (manifest.opt("schemaVersion") != 1 || provenance.opt("schemaVersion") != 1 ||
        provenance.optString("repository") != "Mikeyphw/BakaSU" || provenance.optString("tag") != releaseTag ||
        provenance.optString("channel") != channel || !ManagerReleaseProof.validTag(releaseTag) ||
        provenance.optString("status") != "release-candidate-reviewed" ||
        provenance.optString("compatibilityEvidence") != "reviewed exact-source registry entry" ||
        !ManagerReleaseProof.validSource(provenance.optString("sourceMergedSha")) ||
        !ManagerReleaseProof.validSource(provenance.optString("sourceForkSha")) || provenance.optLong("f06RunId", -1) <= 0
    ) return null
    val artifacts = manifest.optJSONArray("apks") ?: return null
    val proofRows = provenance.optJSONArray("apks") ?: return null
    if (artifacts.length() !in 1..10 || proofRows.length() != artifacts.length()) return null
    val matching = (0 until artifacts.length()).mapNotNull { artifacts.optJSONObject(it) }.filter {
        it.optString("fileName") == identity.fileName && it.opt("versionCode") == identity.versionCode && it.optString("abi") == identity.abi
    }
    if (matching.size != 1) return null
    val compatibility = (0 until artifacts.length()).map { index ->
        val row = artifacts.optJSONObject(index) ?: return null
        CompatibilityRow(
            row.opt("fileName") as? String ?: return null,
            row.opt("versionCode") as? Int ?: return null,
            row.opt("abi") as? String ?: return null,
            row.opt("managerUapi") as? Int ?: return null,
            row.opt("minimumKernelSuVersion") as? Int ?: return null,
        )
    }
    val published = (0 until proofRows.length()).map { index ->
        val row = proofRows.optJSONObject(index) ?: return null
        val size = when (val value = row.opt("sizeBytes")) {
            is Int -> value.toLong()
            is Long -> value
            else -> return null
        }
        ProvenanceRow(row.opt("name") as? String ?: return null, row.opt("sha256") as? String ?: return null, size)
    }
    return ManagerReleaseProof.requirements(identity, compatibility, published, provenance.optString("certificateSha256"), installedSigner)
}
