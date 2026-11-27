package org.bakasu.bakasu.qualification

import org.bakasu.bakasu.data.file.ModuleArchiveIdentity
import org.bakasu.bakasu.data.module.registry.HistoricalZipPolicy
import org.bakasu.bakasu.data.module.registry.HistoricalZipRecord
import org.bakasu.bakasu.data.update.CompatibilityRow
import org.bakasu.bakasu.data.update.ManagerReleaseProof
import org.bakasu.bakasu.data.update.ProvenanceRow
import org.bakasu.bakasu.data.update.ReleaseApkIdentity
import org.bakasu.bakasu.domain.model.ManagerCompatibilityVerdict
import org.bakasu.bakasu.domain.model.evaluateManagerCompatibility

fun main() {
    var count = 0
    fun test(name: String, result: Boolean) {
        check(result) { name }
        count++
        println("PASS $name")
    }
    val digest = "a".repeat(64)
    val signer = "b".repeat(64)
    val first = HistoricalZipRecord("v1", 1, "https://github.com/example/module/releases/download/v1/module.zip", 500, digest, true)
    val latest = first.copy(tag = "v2", versionCode = 2, url = first.url.replace("/v1/", "/v2/"))
    val records = listOf(first, latest)
    fun select(rows: List<HistoricalZipRecord> = records, installed: Int = 1, offered: Int = 2, url: String = latest.url) =
        HistoricalZipPolicy.select(installed, offered, url, rows)
    test("historical exact version", select() == first)
    test("no older version", select(listOf(latest)) == null)
    test("no newer anchor", select(listOf(first)) == null)
    test("wrong anchor version", select(offered = 3) == null)
    test("wrong anchor URL", select(url = latest.url + "?different=true") == null)
    test("duplicate anchor", select(records + latest) == null)
    test("ambiguous anchor claim", HistoricalZipPolicy.claimsAnchor(latest.url, records + latest))
    test("duplicate installed version", select(records + first.copy(tag = "other")) == null)
    test("duplicate selected URL", select(records + first.copy(tag = "v0", versionCode = 0)) == null)
    test("mutable version", select(listOf(first.copy(immutable = false), latest)) == null)
    test("mutable anchor", select(listOf(first, latest.copy(immutable = false))) == null)
    test("missing digest", select(listOf(first.copy(sha256 = ""), latest)) == null)
    test("zero size", select(listOf(first.copy(size = 0), latest)) == null)
    test("oversized ZIP", select(listOf(first.copy(size = Long.MAX_VALUE), latest)) == null)
    test("cross-repository ZIP", select(listOf(first.copy(url = first.url.replace("/example/module/", "/other/module/")), latest)) == null)
    test("wrong tag in asset URL", select(listOf(first.copy(tag = "different"), latest)) == null)
    test("non-ZIP release asset", select(listOf(first.copy(url = first.url.replace(".zip", ".apk")), latest)) == null)
    test("no downgrade", select(installed = 3) == null)
    test("same version not historical", select(installed = 2) == null)
    fun identity(text: String) = runCatching { ModuleArchiveIdentity.verify(text.toByteArray(), "example", 1) }.isSuccess
    test("archive exact identity", identity("id=example\nversionCode=1\n"))
    test("archive wrong ID", !identity("id=other\nversionCode=1\n"))
    test("archive wrong version", !identity("id=example\nversionCode=2\n"))
    test("archive missing version", !identity("id=example\n"))
    test("archive duplicate ID", !identity("id=example\nid=example\nversionCode=1\n"))
    test("archive duplicate version", !identity("id=example\nversionCode=1\nversionCode=1\n"))
    test("archive escaped duplicate", !identity("id=example\n\\u0069d=example\nversionCode=1\n"))
    test("archive invalid version", !identity("id=example\nversionCode=99999999999999\n"))
    val apk = ReleaseApkIdentity("BakaSU_1.0_100-arm64-v8a-release.apk", 100, "arm64-v8a", digest, 200_000)
    val row = CompatibilityRow(apk.fileName, apk.versionCode, apk.abi, 3, 100)
    val proof = ProvenanceRow(apk.fileName, apk.sha256, apk.size)
    fun requirements(candidate: ReleaseApkIdentity = apk, rows: List<CompatibilityRow> = listOf(row), proofs: List<ProvenanceRow> = listOf(proof), installed: String? = signer) =
        ManagerReleaseProof.requirements(candidate, rows, proofs, signer, installed)
    val valid = requirements()
    test("exact APK evidence", valid?.managerUapi == 3 && valid.minimumKernelSuVersion == 100 && valid.abi == apk.abi)
    test("wrong APK digest", requirements(candidate = apk.copy(sha256 = signer)) == null)
    test("wrong APK size", requirements(candidate = apk.copy(size = apk.size + 1)) == null)
    test("wrong APK version", requirements(candidate = apk.copy(versionCode = 101)) == null)
    test("wrong ABI", requirements(candidate = apk.copy(abi = "x86_64")) == null)
    test("missing installed signer", requirements(installed = null) == null)
    test("different installed signer", requirements(installed = digest) == null)
    test("duplicate rows", requirements(rows = listOf(row, row), proofs = listOf(proof, proof)) == null)
    test("missing row", requirements(proofs = emptyList()) == null)
    test("unknown UAPI", requirements(rows = listOf(row.copy(managerUapi = 0))) == null)
    test("unknown minimum version", requirements(rows = listOf(row.copy(minimumKernelSuVersion = 0))) == null)
    test("canonical published asset", ManagerReleaseProof.assetUrl("f07-v1.0", apk.fileName) == "https://github.com/Mikeyphw/BakaSU/releases/download/f07-v1.0/${apk.fileName}")
    test("invalid tag", ManagerReleaseProof.assetUrl("../v1", apk.fileName) == null)
    test("unexpected file", ManagerReleaseProof.assetUrl("f07-v1.0", "other.apk") == null)
    test("exact native ABI", ManagerReleaseProof.supportsArchiveAbi(apk.abi, listOf(apk.abi), setOf(apk.abi)))
    test("unexpected native ABI", !ManagerReleaseProof.supportsArchiveAbi(apk.abi, listOf(apk.abi), setOf(apk.abi, "x86_64")))
    test("wrong device ABI", !ManagerReleaseProof.supportsArchiveAbi(apk.abi, listOf("x86_64"), setOf(apk.abi)))
    test("universal with RISC-V", ManagerReleaseProof.supportsArchiveAbi("universal", listOf("riscv64"), setOf("arm64-v8a", "riscv64")))
    test("universal unknown ABI", !ManagerReleaseProof.supportsArchiveAbi("universal", listOf(apk.abi), setOf(apk.abi, "unknown")))
    test("missing native libraries", !ManagerReleaseProof.supportsArchiveAbi("universal", listOf(apk.abi), emptySet()))
    test("compatible runtime", evaluateManagerCompatibility(valid, true, true, 3, 100) == ManagerCompatibilityVerdict.COMPATIBLE)
    test("incompatible runtime UAPI", evaluateManagerCompatibility(valid, true, true, 4, 100) == ManagerCompatibilityVerdict.INCOMPATIBLE)
    test("incompatible kernel version", evaluateManagerCompatibility(valid, true, true, 3, 99) == ManagerCompatibilityVerdict.INCOMPATIBLE)
    test("unknown root runtime", evaluateManagerCompatibility(valid, true, false, 3, 100) == ManagerCompatibilityVerdict.UNKNOWN)
    test("unknown candidate", evaluateManagerCompatibility(null, true, true, 3, 100) == ManagerCompatibilityVerdict.UNKNOWN)
    println("GAP02_POLICY_PROBE PASS $count")
}
