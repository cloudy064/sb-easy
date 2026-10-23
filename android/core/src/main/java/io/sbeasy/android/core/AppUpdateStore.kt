package io.sbeasy.android.core

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.OutputStream
import java.security.PublicKey
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject

data class CachedApp(val release: AppRelease, val file: File)
data class AppUpdateSnapshot(val catalog: VerifiedAppCatalog? = null, val revoked: Map<Long, String> = emptyMap(),
    val cached: List<CachedApp> = emptyList(), val received: Long = 0, val total: Long = 0, val busy: Boolean = false,
    val error: String = "", val trustedKeyCount: Int = 0)

/** Application update trust is local installation state and is excluded from preference roaming. */
object AppUpdateStore {
    private val operations = Mutex()
    private val mutable = MutableStateFlow(AppUpdateSnapshot())
    val state = mutable.asStateFlow()
    private lateinit var context: Context
    private lateinit var stateFile: AtomicFile
    private lateinit var cache: File
    private var keys: Map<String, PublicKey> = emptyMap()
    private var initializationError: String? = null
    private val transfer = AppUpdateTransfer()

    fun initialize(owner: Context, trust: String) {
        context = owner.applicationContext
        stateFile = AtomicFile(File(context.filesDir, "app-catalog-state.json"))
        cache = File(context.filesDir, "app-update-cache").apply { mkdirs() }
        try {
            keys = AppCatalog.trustedKeys(trust)
            var catalog: VerifiedAppCatalog? = null
            var revoked = emptyMap<Long, String>()
            if (stateFile.baseFile.exists() || File(stateFile.baseFile.path + ".bak").exists()) {
                val root = stateFile.openRead().use { StrictJson.objectValue(PreferencesEnvelope.utf8(AppRuntimeProvenance.readBounded(it, 4 * 1024 * 1024))) }
                AppCatalog.fields(root, setOf("catalog", "revoked"))
                catalog = AppCatalog.verify(root.getString("catalog"), keys, requireFresh = false)
                val values = root.getJSONObject("revoked"); require(values.length() <= 8192)
                revoked = values.keys().asSequence().associate { name ->
                    val build = name.toLong(); require(build in 1..2100000000 && build.toString() == name)
                    build to values.getString(name).also { require(it.length in 1..480) }
                }
                require(catalog.revocations.all { (build, _) -> build in revoked }) { "撤销状态不完整" }
            }
            initializationError = null
            mutable.value = AppUpdateSnapshot(catalog = catalog, revoked = revoked, trustedKeyCount = keys.size)
            mutable.value = mutable.value.copy(cached = cachedPackages())
        } catch (_: Exception) {
            initializationError = "本机应用更新信任记录无效，更新与缓存恢复已关闭；请恢复可信安装配置"
            mutable.value = AppUpdateSnapshot(error = initializationError!!, trustedKeyCount = keys.size)
        }
    }
    private fun ready() { check(::context.isInitialized && initializationError == null) { initializationError ?: "应用更新尚未初始化" } }
    fun compatible(release: AppRelease): Boolean = initializationError == null && release.build !in mutable.value.revoked && AppPackagePolicy.compatible(context, release)
    private fun requireAllowed(release: AppRelease) {
        ready(); require(compatible(release)) { mutable.value.revoked[release.build]?.let { "应用版本已撤销：$it" } ?: "APK 与当前应用签名、CPU 或系统不兼容" }
    }
    suspend fun refresh(rawUrl: String) = operations.withLock {
        ready(); require(keys.isNotEmpty()) { "本应用尚未配置更新发布者公钥" }
        val url = AppCatalog.https(rawUrl)
        mutable.value = mutable.value.copy(busy = true, received = 0, total = 0, error = "")
        try {
            val text = withContext(Dispatchers.IO) { transfer.catalog(url) }
            acceptLocked(text)
        } finally { mutable.value = mutable.value.copy(busy = false) }
    }
    suspend fun accept(text: String) = operations.withLock { acceptLocked(text) }
    private suspend fun acceptLocked(text: String) {
        ready()
        val next = withContext(Dispatchers.Default) { AppCatalog.verify(text, keys) }
        val previous = mutable.value
        previous.catalog?.let { AppCatalog.requireMonotonic(next, it) }
        val revoked = previous.revoked + next.revocations
        require(revoked.size <= 8192) { "本机撤销记录达到上限，请通过可信发行渠道更新主应用" }
        withContext(NonCancellable + Dispatchers.IO) {
            val serialized = JSONObject().put("catalog", next.envelope).put("revoked", JSONObject(revoked.mapKeys { it.key.toString() })).toString()
            require(serialized.toByteArray(Charsets.UTF_8).size <= 4 * 1024 * 1024) { "本机更新信任状态超过保存上限" }
            writeAtomic(stateFile, serialized)
            mutable.value = previous.copy(catalog = next, revoked = revoked, error = "")
            mutable.value = mutable.value.copy(cached = cachedPackages())
            if (previous.catalog?.payloadSha256 != next.payloadSha256) {
                // A changed directory invalidates confirmation already staged under the previous decision.
                val installer = context.packageManager.packageInstaller
                val sessions = installer.mySessions.filter { it.appPackageName == context.packageName }
                sessions.forEach { runCatching { installer.abandonSession(it.sessionId) } }
                if (sessions.isNotEmpty()) context.getSharedPreferences("app_update_install", Context.MODE_PRIVATE).edit()
                    .putString("status", "应用目录已变化，之前未完成的安装会话已取消；请重新验证并确认安装。").remove("nonce").apply()
            }
        }
    }

    suspend fun download(release: AppRelease): CachedApp = operations.withLock {
        ready()
        val catalog = requireNotNull(mutable.value.catalog) { "请先读取已签名应用目录" }
        require(catalog.fresh() && release in catalog.releases) { "应用目录已过期或目标版本不属于当前目录" }
        requireAllowed(release)
        require(release.build > AppPackagePolicy.currentBuild(context)) { "在线更新必须使用更高的版本号" }
        mutable.value = mutable.value.copy(busy = true, received = 0, total = release.bytes, error = "")
        try { withContext(Dispatchers.IO) {
            backupInstalled(catalog)
            val folder = folder(release).apply { mkdirs() }
            val part = File(folder, "download.part")
            try {
                transfer.artifact(release, part) { received -> mutable.value = mutable.value.copy(received = received) }
                AppPackagePolicy.inspect(context, part, release)
                require(catalog.fresh()) { "应用目录在下载期间过期，请刷新目录后重试" }
                requireAllowed(release)
                writeAtomic(AtomicFile(File(folder, "receipt.json")), catalog.envelope)
                val file = File(folder, "app.apk"); check(part.renameTo(file)) { "无法提交已验证 APK" }
                trimCache(release)
                mutable.value = mutable.value.copy(cached = cachedPackages())
                CachedApp(release, file)
            } finally { part.delete() }
        } } finally { mutable.value = mutable.value.copy(busy = false) }
    }

    /** Hold the catalog lock through use, so a concurrent refresh cannot revoke a staged install halfway through commit. */
    suspend fun <T> withVerifiedCached(candidate: CachedApp, block: suspend (File) -> T): T = operations.withLock {
        requireAllowed(candidate.release)
        val current = cachedPackages().firstOrNull { it.release == candidate.release && it.file.canonicalPath == candidate.file.canonicalPath }
            ?: error("缓存回执已变化或签名不再受信任")
        withContext(Dispatchers.IO) { AppPackagePolicy.inspect(context, current.file, current.release) }
        block(current.file)
    }

    suspend fun exportRecovery(candidate: CachedApp, output: OutputStream) = withVerifiedCached(candidate) { file ->
        withContext(Dispatchers.IO) {
            ZipOutputStream(output).use { zip ->
                zip.putNextEntry(ZipEntry("sb-easy-${candidate.release.version}-${candidate.release.build}.apk")); file.inputStream().use { it.copyTo(zip) }; zip.closeEntry()
                zip.putNextEntry(ZipEntry("signed-catalog.json")); File(requireNotNull(file.parentFile), "receipt.json").inputStream().use { it.copyTo(zip) }; zip.closeEntry()
                zip.putNextEntry(ZipEntry("RECOVERY.txt")); zip.write(("sb-easy Android verified recovery\n" +
                    "APK SHA-256: ${candidate.release.sha256}\nCertificate SHA-256: ${candidate.release.signer}\n" +
                    "Export encrypted preferences separately BEFORE uninstalling. Extract this ZIP outside app-private storage.\n" +
                    "Android blocks versionCode downgrade. Manually uninstall the current app, then install this APK through Android and import the encrypted preference backup.\n" +
                    "Uninstall deletes enrollment tokens, WireGuard keys, local trust/revocation state and app-private cache; these secrets are not included in portable preferences. Re-enroll managed devices.\n" +
                    "This is not an atomic or lossless rollback. Fetch a fresh signed catalog to restore the latest revocations after reinstall.\n").toByteArray(Charsets.UTF_8)); zip.closeEntry()
            }
        }
    }

    /** Export before installing; the archive remains accessible if the next app cannot start. */
    suspend fun exportInstallRecovery(candidate: CachedApp, encryptedPreferences: String, output: OutputStream): AppInstallRecovery = withVerifiedCached(candidate) {
        withContext(Dispatchers.IO) {
            val installedBuild = AppPackagePolicy.currentBuild(context)
            val installedSha = HttpDebugPackagePolicy.digest(File(context.applicationInfo.sourceDir))
            backupInstalled(requireNotNull(mutable.value.catalog) { "应用目录不可用" })
            val candidates = cachedPackages()
            val current = candidates.firstOrNull { it.release.build == installedBuild && it.release.sha256 == installedSha }
            val recovery = current ?: candidates.firstOrNull { it.release.build < installedBuild && runCatching { AppPackagePolicy.inspect(context, it.file, it.release) }.isSuccess }
                ?: candidate // A revoked old version must never be exported as a rollback option.
            requireAllowed(recovery.release)
            AppPackagePolicy.inspect(context, recovery.file, recovery.release)
            val receipt = AtomicFile(File(requireNotNull(recovery.file.parentFile), "receipt.json")).openRead().use {
                PreferencesEnvelope.utf8(AppRuntimeProvenance.readBounded(it, PluginCatalog.MAX_ENVELOPE))
            }
            val hash = AppRecoveryBundle.write(recovery.file, recovery.release, receipt, encryptedPreferences, installedBuild, candidate.release.build, output)
            AppInstallRecovery(installedBuild, installedSha, candidate.release.build, candidate.release.sha256, recovery.release.build, recovery.release.sha256, hash)
        }
    }

    private fun backupInstalled(catalog: VerifiedAppCatalog) {
        val app = context.applicationInfo
        require(app.splitSourceDirs.isNullOrEmpty()) { "当前应用使用分拆安装包，无法备份为单一 APK；请使用可信发行渠道处理更新" }
        if (AppPackagePolicy.currentBuild(context) in mutable.value.revoked) return // Never retain revoked code as a recovery option.
        val source = File(app.sourceDir)
        val digest = HttpDebugPackagePolicy.digest(source)
        val build = AppPackagePolicy.currentBuild(context)
        val oldCache = cachedPackages().firstOrNull { it.release.build == build && it.release.sha256 == digest }
        val release = catalog.releases.firstOrNull { it.build == build && it.sha256 == digest } ?: oldCache?.release
            ?: error("目录未包含当前安装包的签名恢复记录；请发布包含当前版本的目录后再更新")
        requireAllowed(release)
        AppPackagePolicy.inspect(context, source, release)
        if (oldCache != null && runCatching { AppPackagePolicy.inspect(context, oldCache.file, release) }.isSuccess) return
        // A prior cache supplies its own exact signed receipt; never label it with an unrelated latest catalog.
        val envelope = if (release in catalog.releases) catalog.envelope else File(requireNotNull(oldCache?.file?.parentFile), "receipt.json").readText()
        val folder = folder(release).apply { mkdirs() }; val part = File(folder, "backup.part")
        try {
            source.inputStream().use { input -> part.outputStream().use { output -> input.copyTo(output); output.fd.sync() } }
            AppPackagePolicy.inspect(context, part, release)
            writeAtomic(AtomicFile(File(folder, "receipt.json")), envelope)
            check(part.renameTo(File(folder, "app.apk"))) { "无法保存当前 APK 恢复副本" }
            mutable.value = mutable.value.copy(cached = cachedPackages())
        } finally { part.delete() }
    }
    private fun folder(release: AppRelease) = File(cache, "${release.build}-${release.sha256}")
    private fun cachedPackages(): List<CachedApp> = cache.listFiles().orEmpty().filter { it.isDirectory && it.name.matches(Regex("[0-9]{1,10}-[0-9a-f]{64}")) }.mapNotNull { folder ->
        runCatching {
            val receipt = AtomicFile(File(folder, "receipt.json"))
            val text = receipt.openRead().use { PreferencesEnvelope.utf8(AppRuntimeProvenance.readBounded(it, PluginCatalog.MAX_ENVELOPE)) }
            val catalog = AppCatalog.verify(text, keys, requireFresh = false)
            val release = catalog.releases.single { "${it.build}-${it.sha256}" == folder.name }
            require(release.build !in mutable.value.revoked && release.build !in catalog.revocations)
            val file = File(folder, "app.apk"); require(file.isFile && file.length() == release.bytes)
            CachedApp(release, file)
        }.getOrNull()
    }.sortedByDescending { it.release.build }
    private fun trimCache(incoming: AppRelease) {
        val installed = AppPackagePolicy.currentBuild(context)
        val rows = cachedPackages()
        val retained = (rows.filter { it.release == incoming || it.release.build == installed } + rows).distinctBy { it.file.parent }.take(2).map { it.file.parent }.toSet()
        cache.listFiles().orEmpty().filter { it.isDirectory && it.name.matches(Regex("[0-9]{1,10}-[0-9a-f]{64}")) && it.path !in retained }.forEach { folder ->
            listOf("app.apk", "receipt.json", "receipt.json.bak", "download.part", "backup.part").forEach { File(folder, it).delete() }; folder.delete()
        }
    }
    private fun writeAtomic(file: AtomicFile, text: String) {
        val output = file.startWrite()
        try { output.write(text.toByteArray(Charsets.UTF_8)); file.finishWrite(output) }
        catch (error: Throwable) { file.failWrite(output); throw error }
    }
}
