package org.bakasu.bakasu.data.module

import com.topjohnwu.superuser.io.SuFile
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.bakasu.bakasu.data.module.registry.KernelSuRegistryRepository
import org.bakasu.bakasu.data.network.LocalNetworkPermissionRequiredException
import org.bakasu.bakasu.data.network.NetworkRequestRepository
import org.bakasu.bakasu.data.network.NetworkStatusRepository
import org.bakasu.bakasu.data.shell.KsuCliRepository
import org.bakasu.bakasu.domain.model.InstalledModule
import org.bakasu.bakasu.domain.model.InstalledModulesState
import org.bakasu.bakasu.domain.model.MetaModuleStatus
import org.bakasu.bakasu.domain.model.ModuleUpdateMetadata
import org.json.JSONArray
import org.json.JSONObject

class ModuleRepository(
    private val networkStatusRepository: NetworkStatusRepository,
    private val networkRequestRepository: NetworkRequestRepository,
    private val ksuCliRepository: KsuCliRepository,
    private val registry: KernelSuRegistryRepository,
) {
    private val refreshMutex = Mutex()
    private val mutableInstalledModules = MutableStateFlow(InstalledModulesState())
    val installedModules: StateFlow<InstalledModulesState> =
        mutableInstalledModules.asStateFlow()

    suspend fun refreshInstalledModules(
        manual: Boolean,
        checkUpdates: Boolean,
    ): Result<Boolean> = refreshMutex.withLock {
        withContext(Dispatchers.IO) {
            mutableInstalledModules.update { it.copy(refreshing = true) }
            runCatching {
                val previous = mutableInstalledModules.value.modules
                val modules = parseModules(ksuCliRepository.listModules())
                val requiresMount = coroutineScope {
                    modules.map { module ->
                        async(Dispatchers.IO) {
                            val directory = "/data/adb/modules/${module.id}"
                            SuFile.open("$directory/system").exists() &&
                                !SuFile.open("$directory/skip_mount").exists() &&
                                !SuFile.open("$directory/disable").exists() &&
                                !SuFile.open("$directory/remove").exists()
                        }
                    }.awaitAll().any { it }
                }
                mutableInstalledModules.value = InstalledModulesState(
                    modules = modules,
                    refreshing = false,
                    hasModuleRequireMount = requiresMount,
                    hasMagisk = ksuCliRepository.hasMagisk(),
                    metaModuleStatus = getMetaModuleStatus(),
                )

                if (!checkUpdates || !networkStatusRepository.isAvailable()) return@runCatching false

                val updateResults = coroutineScope {
                    modules.map { module ->
                        async(Dispatchers.IO) {
                            // Fetch one candidate per module, not twice for update + reinstall.
                            // Preserve prior resolved metadata on a non-manual refresh.
                            val cached = previous.firstOrNull {
                                it.id == module.id && it.versionCode == module.versionCode &&
                                    it.updateJson == module.updateJson
                            }
                            val shouldCheck = manual || cached == null ||
                                module.remove || module.update || !module.enabled
                            val result = if (shouldCheck) {
                                fetchUpdateMetadata(module.updateJson)
                            } else {
                                Result.success(cached?.moduleUpdate ?: cached?.moduleReinstall)
                            }
                            val error = result.exceptionOrNull()
                            if (error is CancellationException) throw error
                            val candidate = result.getOrNull()
                            val offered = candidate?.takeIf {
                                !module.remove && !module.update &&
                                    it.versionCode >= module.versionCode &&
                                    isSecureReinstallZipUrl(it.zipUrl)
                            }
                            val historical = if (offered != null && offered.versionCode > module.versionCode) {
                                if (shouldCheck) {
                                    registry.historicalReinstall(module.id, module.updateJson, module.versionCode, offered)
                                } else {
                                    cached?.moduleReinstall?.takeIf { previous ->
                                        previous.historicalProof?.let(registry::isCurrent) == true
                                    }
                                }
                            } else {
                                null
                            }
                            module.copy(
                                moduleUpdate = candidate?.takeIf { it.versionCode > module.versionCode },
                                moduleReinstall = historical ?: offered,
                            ) to (error is LocalNetworkPermissionRequiredException)
                        }
                    }.awaitAll()
                }
                mutableInstalledModules.update { current -> current.copy(modules = updateResults.map { it.first }) }
                updateResults.any { it.second }
            }.onFailure {
                mutableInstalledModules.update { current -> current.copy(refreshing = false) }
                if (it is CancellationException) throw it
            }
        }
    }

    suspend fun calculateInstalledModuleSize(moduleId: String): Long = withContext(Dispatchers.IO) {
        runCatching {
            val result = ksuCliRepository.getRootShell().newJob()
                .add("/data/adb/ksu/bin/busybox du -sb /data/adb/modules/$moduleId")
                .to(ArrayList(), null)
                .exec()
            if (result.isSuccess) {
                result.out.firstOrNull()?.split('\t')?.firstOrNull()?.toLongOrNull() ?: 0L
            } else {
                0L
            }
        }.getOrDefault(0L)
    }

    fun updateCachedEnabled(moduleId: String, enabled: Boolean) {
        mutableInstalledModules.update { current ->
            current.copy(
                modules = current.modules.map { module ->
                    if (module.dirId == moduleId) module.copy(enabled = enabled) else module
                },
            )
        }
    }

    suspend fun setModuleEnabled(moduleId: String, enabled: Boolean): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching { check(ksuCliRepository.toggleModule(moduleId, enabled)) }
            .onSuccess { updateCachedEnabled(moduleId, enabled) }
    }

    suspend fun setModuleRemoved(moduleId: String, removed: Boolean): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            check(
                if (removed) {
                    ksuCliRepository.uninstallModule(moduleId)
                } else {
                    ksuCliRepository.undoUninstallModule(moduleId)
                },
            )
        }
    }

    // Retains the original Update behavior; exact-version candidates are only used
    // by the separate, user-confirmed Reinstall action.
    suspend fun checkUpdate(url: String, currentVersionCode: Int): Result<ModuleUpdateMetadata?> = fetchUpdateMetadata(url).map { metadata ->
        metadata?.takeIf { it.versionCode > currentVersionCode }
    }

    private suspend fun fetchUpdateMetadata(url: String): Result<ModuleUpdateMetadata?> {
        if (url.isBlank()) return Result.success(null)
        return networkRequestRepository.fetch(url, detectLocalNetworkPermission = true).mapCatching { body ->
            val json = JSONObject(body)
            val onlineVersionCode = json.optInt("versionCode", -1)
            val zipUrl = json.optString("zipUrl").trim()
            if (onlineVersionCode < 0 || zipUrl.isBlank()) {
                null
            } else {
                ModuleUpdateMetadata(
                    zipUrl = zipUrl,
                    version = json.optString("version").replace(
                        Regex("[^a-zA-Z0-9.\\-_]"),
                        "_",
                    ),
                    changelog = json.optString("changelog"),
                    versionCode = onlineVersionCode,
                )
            }
        }
    }

    private fun isSecureReinstallZipUrl(url: String): Boolean = runCatching {
        val uri = java.net.URI(url)
        uri.scheme.equals("https", ignoreCase = true) &&
            !uri.host.isNullOrBlank() && uri.userInfo == null
    }.getOrDefault(false)

    private fun parseModules(raw: String): List<InstalledModule> {
        val array = JSONArray(raw)
        return (0 until array.length()).map { index ->
            val value = array.getJSONObject(index)
            val id = value.getString("id")
            InstalledModule(
                id = id,
                name = value.optString("name"),
                author = value.optString("author", "Unknown"),
                version = value.optString("version", "Unknown"),
                versionCode = value.getIntCompat("versionCode"),
                description = value.optString("description"),
                enabled = value.getBooleanCompat("enabled"),
                update = value.getBooleanCompat("update"),
                remove = value.getBooleanCompat("remove"),
                updateJson = value.optString("updateJson"),
                hasWebUi = value.getBooleanCompat("web"),
                hasActionScript = value.getBooleanCompat("action"),
                metamodule = value.getBooleanCompat("metamodule"),
                actionIconPath = value.optString("actionIcon").takeIf(String::isNotBlank),
                webUiIconPath = value.optString("webuiIcon").takeIf(String::isNotBlank),
                dirId = value.optString("dir_id", id),
                moduleUpdate = null,
            )
        }
    }

    private fun getMetaModuleStatus(): MetaModuleStatus {
        val directory = "/data/adb/metamodule"
        return when {
            !SuFile.open("$directory/module.prop").exists() -> MetaModuleStatus.MISSING
            SuFile.open("$directory/remove").exists() -> MetaModuleStatus.REMOVED
            SuFile.open("$directory/disable").exists() -> MetaModuleStatus.DISABLED
            else -> MetaModuleStatus.ACTIVE
        }
    }
}

private fun JSONObject.getBooleanCompat(key: String, default: Boolean = false): Boolean = if (!has(key)) {
    default
} else {
    when (val value = opt(key)) {
        null -> default
        is Boolean -> value
        is String -> value.equals("true", ignoreCase = true) || value == "1"
        is Number -> value.toInt() != 0
        else -> default
    }
}

private fun JSONObject.getIntCompat(key: String, default: Int = 0): Int = if (!has(key)) {
    default
} else {
    when (val value = opt(key)) {
        null -> default
        is Number -> value.toInt()
        is String -> value.toIntOrNull() ?: default
        else -> default
    }
}
