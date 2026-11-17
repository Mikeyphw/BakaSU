package org.bakasu.bakasu.data.file

import android.content.Context
import android.net.Uri
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.Properties
import org.apache.commons.compress.archivers.zip.ZipFile

/** Immutable private copy before module-ID verification and flashing. */
object ReinstallArchiveVerifier {
    private const val MAX_ZIP_BYTES = 1024L * 1024L * 1024L
    private const val MAX_MODULE_PROP_BYTES = 65536
    private val safeId = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    private val sha256Pattern = Regex("[a-f0-9]{64}")

    fun prepare(
        context: Context,
        uri: Uri,
        expectedModuleId: String,
        expectedSha256: String?,
        expectedSize: Long?,
    ): File {
        require(safeId.matches(expectedModuleId)) { "Invalid installed module ID" }
        require(expectedSha256 == null || sha256Pattern.matches(expectedSha256)) { "Invalid digest" }
        require(expectedSize == null || expectedSize in 1..MAX_ZIP_BYTES) { "Invalid expected size" }
        val copy = File.createTempFile("reinstall-", ".zip", context.cacheDir)
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            var written = 0L
            val input = context.contentResolver.openInputStream(uri)
                ?: throw IOException("Cannot open downloaded archive")
            input.use { source ->
                copy.outputStream().use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val amount = source.read(buffer)
                        if (amount < 0) break
                        written += amount
                        require(written in 1..MAX_ZIP_BYTES) { "ZIP exceeds safe size" }
                        digest.update(buffer, 0, amount)
                        output.write(buffer, 0, amount)
                    }
                }
            }
            require(written > 0L && (expectedSize == null || written == expectedSize)) {
                "ZIP size differs from verified release"
            }
            val actualSha = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
            require(expectedSha256 == null || actualSha == expectedSha256) {
                "ZIP checksum differs from verified release"
            }
            ZipFile.builder().setFile(copy).setIgnoreLocalFileHeader(false).get().use { zip ->
                val names = mutableSetOf<String>()
                val entries = zip.entries
                var totalUncompressed = 0L
                val buffer = ByteArray(64 * 1024)
                while (entries.hasMoreElements()) {
                    require(names.size < 10000) { "ZIP contains too many entries" }
                    val entry = entries.nextElement()
                    val name = entry.name
                    require(entry.size >= 0L && entry.size <= MAX_ZIP_BYTES &&
                        totalUncompressed <= MAX_ZIP_BYTES * 4 - entry.size) {
                        "ZIP decompressed size exceeds safe bound"
                    }
                    val components = name.replace('\\', '/').split('/')
                    require(name.isNotBlank() && !name.startsWith('/') && !name.contains('\\') &&
                        components.none { it == ".." || it == "." } && !entry.isUnixSymlink &&
                        names.add(name)) {
                        "Unsafe ZIP entry"
                    }
                    // Trust neither declared uncompressed size nor ZIP compression ratio.
                    if (!entry.isDirectory) {
                        var actualEntryBytes = 0L
                        zip.getInputStream(entry).use { content ->
                            while (true) {
                                val n = content.read(buffer)
                                if (n < 0) break
                                actualEntryBytes += n
                                require(actualEntryBytes <= MAX_ZIP_BYTES &&
                                    totalUncompressed <= MAX_ZIP_BYTES * 4 - n) {
                                    "ZIP actual extracted data exceeds safe bound"
                                }
                                totalUncompressed += n
                            }
                        }
                        require(actualEntryBytes == entry.size) {
                            "ZIP entry size does not match actual data"
                        }
                    }
                }
                val props = zip.getEntry("module.prop") ?: throw IOException("module.prop missing")
                require(!props.isDirectory && props.size in 1..MAX_MODULE_PROP_BYTES.toLong()) {
                    "Invalid module.prop"
                }
                val bytes = zip.getInputStream(props).use { source ->
                    val output = java.io.ByteArrayOutputStream()
                    val buffer = ByteArray(4096)
                    while (true) {
                        val amount = source.read(buffer)
                        if (amount < 0) break
                        require(output.size() + amount <= MAX_MODULE_PROP_BYTES) { "Oversized module.prop" }
                        output.write(buffer, 0, amount)
                    }
                    output.toByteArray()
                }
                val prop = Properties().also { it.load(bytes.inputStream()) }
                require(prop.getProperty("id") == expectedModuleId) {
                    "ZIP module ID is different from installed module"
                }
            }
            return copy
        } catch (failure: Exception) {
            copy.delete()
            throw failure
        }
    }
}
