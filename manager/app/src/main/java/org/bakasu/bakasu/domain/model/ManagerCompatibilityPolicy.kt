package org.bakasu.bakasu.domain.model

/** Candidate requirements must be derived from this candidate's published build metadata.
 * The currently installed manager UAPI is NOT evidence of a candidate's UAPI.
 */
data class ManagerCompatibilityRequirements(
    val managerUapi: Int,
    val minimumKernelSuVersion: Int,
    val signerCertificateSha256: String? = null,
    val abi: String? = null,
)

enum class ManagerCompatibilityVerdict {
    COMPATIBLE,
    INCOMPATIBLE,
    UNKNOWN,
}

/** Fail closed on missing or unverifiable runtime/candidate evidence. */
fun evaluateManagerCompatibility(
    candidate: ManagerCompatibilityRequirements?,
    isManager: Boolean,
    rootAvailable: Boolean,
    kernelUapiVersion: Int?,
    kernelSuVersion: Int?,
): ManagerCompatibilityVerdict {
    if (candidate == null || candidate.managerUapi <= 0 || candidate.minimumKernelSuVersion <= 0) {
        return ManagerCompatibilityVerdict.UNKNOWN
    }
    if (!isManager || !rootAvailable || kernelUapiVersion == null || kernelUapiVersion <= 0) {
        return ManagerCompatibilityVerdict.UNKNOWN
    }
    if (kernelUapiVersion != candidate.managerUapi) return ManagerCompatibilityVerdict.INCOMPATIBLE
    if (kernelSuVersion == null || kernelSuVersion <= 0) return ManagerCompatibilityVerdict.UNKNOWN
    if (kernelSuVersion < candidate.minimumKernelSuVersion) return ManagerCompatibilityVerdict.INCOMPATIBLE
    return ManagerCompatibilityVerdict.COMPATIBLE
}
