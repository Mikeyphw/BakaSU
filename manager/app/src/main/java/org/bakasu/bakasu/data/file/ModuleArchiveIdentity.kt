package org.bakasu.bakasu.data.file

import java.util.Properties

/** The version and ID are taken from the archive, not from a filename or remote label. */
internal object ModuleArchiveIdentity {
    fun verify(bytes: ByteArray, expectedModuleId: String, expectedVersionCode: Int) {
        require(expectedVersionCode >= 0) { "Invalid expected archive version" }
        val prop = object : Properties() {
            override fun put(key: Any, value: Any): Any? {
                require((key != "id" && key != "versionCode") || !containsKey(key)) { "Duplicate module identity" }
                return super.put(key, value)
            }
        }.also { it.load(bytes.inputStream()) }
        require(prop.getProperty("id") == expectedModuleId) { "ZIP module ID is different from installed module" }
        require(prop.getProperty("versionCode")?.toIntOrNull() == expectedVersionCode) { "ZIP module version differs from selected release" }
    }
}
