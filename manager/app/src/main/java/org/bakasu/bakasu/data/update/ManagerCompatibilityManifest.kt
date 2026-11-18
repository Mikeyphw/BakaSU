package org.bakasu.bakasu.data.update

import org.bakasu.bakasu.domain.model.ManagerCompatibilityRequirements
import org.json.JSONObject

/** Parse only build-specific requirements tied to the exact APK file, ABI and version. */
internal fun parseManagerCompatibilityManifest(
    manifest: JSONObject,
    fileName: String,
    versionCode: Int,
    abi: String,
): ManagerCompatibilityRequirements? {
    if (manifest.optInt("schemaVersion", -1) != 1) return null
    val artifacts = manifest.optJSONArray("apks") ?: return null
    val matching = (0 until artifacts.length())
        .mapNotNull { artifacts.optJSONObject(it) }
        .filter {
            it.optString("fileName") == fileName &&
                it.optInt("versionCode", -1) == versionCode &&
                it.optString("abi") == abi
        }
    if (matching.size != 1) return null
    val entry = matching.single()
    val managerUapi = entry.optInt("managerUapi", -1)
    val minimumVersion = entry.optInt("minimumKernelSuVersion", -1)
    if (managerUapi <= 0 || minimumVersion <= 0) return null
    return ManagerCompatibilityRequirements(managerUapi, minimumVersion)
}
