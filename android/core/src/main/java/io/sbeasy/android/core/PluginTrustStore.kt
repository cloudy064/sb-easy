package io.sbeasy.android.core

import android.content.Context
import android.os.Build
import android.util.AtomicFile
import java.io.File
import java.security.PublicKey
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject

data class CachedPlugin(val release: PluginRelease, val file: File)
data class PluginStoreSnapshot(val catalog: VerifiedPluginCatalog? = null, val revoked: Map<String, String> = emptyMap(),
    val cached: List<CachedPlugin> = emptyList(), val received: Long = 0, val total: Long = 0, val busy: Boolean = false, val error: String = "", val trustedKeyCount: Int = 0)

/** Trust state belongs to this host installation; it is never part of preference roaming. */
object PluginTrustStore {
    private val operations = Mutex()
    private val mutable = MutableStateFlow(PluginStoreSnapshot())
    val state = mutable.asStateFlow()
    private lateinit var context: Context
    private lateinit var stateFile: AtomicFile
    private lateinit var cache: File
    private var keys: Map<String, PublicKey> = emptyMap()
    private var initializationError: String? = null
    var hostVersion = ""
        private set
    private val http = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
        .connectTimeout(15, TimeUnit.SECONDS).readTimeout(20, TimeUnit.SECONDS).callTimeout(180, TimeUnit.SECONDS).build()

    fun initialize(owner: Context, trust: String, version: String) {
        context = owner.applicationContext; hostVersion = version
        stateFile = AtomicFile(File(context.filesDir, "plugin-catalog-state.json"))
        cache = File(context.filesDir, "plugin-cache").apply { mkdirs() }
        try {
            keys = PluginCatalog.trustedKeys(trust)
            var catalog: VerifiedPluginCatalog? = null
            var revoked = emptyMap<String, String>()
            if (stateFile.baseFile.exists()) {
                val root = StrictJson.objectValue(stateFile.openRead().use { PreferencesEnvelope.utf8(it.readBytes()) })
                catalog = PluginCatalog.verify(root.getString("catalog"), keys, requireFresh = false)
                val records = root.getJSONObject("revoked")
                revoked = records.keys().asSequence().associateWith { records.getString(it) }
                require(catalog.revocations.all { it.key in revoked }) { "本机撤销记录不完整" }
            }
            initializationError = null
            mutable.value = PluginStoreSnapshot(catalog = catalog, revoked = revoked, trustedKeyCount = keys.size)
            mutable.value = mutable.value.copy(cached = cachedPackages())
        } catch (_: Exception) {
            initializationError = "本机插件信任记录无效，请恢复可信的应用/目录配置；插件未启用"
            mutable.value = PluginStoreSnapshot(error = initializationError!!, trustedKeyCount = keys.size)
        }
    }

    fun requireNotRevoked(build: Long) {
        check(::context.isInitialized && initializationError == null) { initializationError ?: "插件信任设置尚未初始化" }
        val reason = mutable.value.revoked["android/http-debug/$build"]
        require(reason == null) { "此插件版本已被撤销：$reason" }
    }

    fun compatible(release: PluginRelease): Boolean = runCatching {
        release.id == "http-debug" && release.platform == "android" && release.packageName == HttpDebug.PACKAGE &&
            release.permissions.toSet() == HttpDebugPackagePolicy.CAPABILITIES && release.revocationKey !in mutable.value.revoked &&
            release.compatible(hostVersion, requireNotNull(VpnRuntimeState.state.value.coreVersion), HttpDebugPackagePolicy.HOST_API,
                Build.VERSION.SDK_INT, Build.SUPPORTED_ABIS.toList())
    }.getOrDefault(false)

    suspend fun refresh(url: String) = operations.withLock {
        check(initializationError == null) { requireNotNull(initializationError) }
        check(keys.isNotEmpty()) { "当前应用尚未配置发布者目录公钥，不能联网安装插件" }
        val address = url.toHttpUrlOrNull()
        require(address?.isHttps == true && address.username.isEmpty() && address.password.isEmpty() && address.fragment == null) { "目录地址必须为不含账户信息的 HTTPS" }
        mutable.value = mutable.value.copy(busy = true, received = 0, total = 0, error = "")
        try {
            val text = withContext(Dispatchers.IO) {
                http.newCall(Request.Builder().url(address).header("User-Agent", "sb-easy-android/plugins").build()).execute().use { response ->
                    require(response.isSuccessful) { "读取目录失败：HTTP ${response.code}" }
                    val body = requireNotNull(response.body)
                    require(body.contentLength() <= PluginCatalog.MAX_ENVELOPE) { "目录超过 1 MiB" }
                    val buffer = okio.Buffer(); val source = body.source()
                    while (buffer.size <= PluginCatalog.MAX_ENVELOPE) {
                        currentCoroutineContext().ensureActive()
                        if (source.read(buffer, minOf(8192L, PluginCatalog.MAX_ENVELOPE + 1L - buffer.size)) == -1L) break
                    }
                    require(buffer.size <= PluginCatalog.MAX_ENVELOPE) { "目录超过 1 MiB" }
                    PreferencesEnvelope.utf8(buffer.readByteArray())
                }
            }
            acceptLocked(text)
        } catch (error: Exception) { mutable.value = mutable.value.copy(error = error.message.orEmpty()); throw error }
        finally { mutable.value = mutable.value.copy(busy = false) }
    }

    suspend fun accept(text: String) = operations.withLock { acceptLocked(text) }

    private suspend fun acceptLocked(text: String) {
        check(initializationError == null) { requireNotNull(initializationError) }
        val next = withContext(Dispatchers.Default) { PluginCatalog.verify(text, keys) }
        val previous = mutable.value
        previous.catalog?.let { PluginCatalog.requireMonotonic(next, it.sequence, it.payloadSha256) }
        val revoked = previous.revoked + next.revocations.associate { it.key to it.reason }
        withContext(NonCancellable) {
        withContext(Dispatchers.IO) {
            val serialized = JSONObject().put("catalog", next.envelope).put("revoked", JSONObject(revoked)).toString()
            val output = stateFile.startWrite()
            try { output.write(serialized.toByteArray(Charsets.UTF_8)); stateFile.finishWrite(output) }
            catch (failure: Throwable) { stateFile.failWrite(output); throw failure }
        }
        mutable.value = previous.copy(catalog = next, revoked = revoked, error = "")
        val installed = HttpDebugPackagePolicy.installed(context)
        if (installed != null && "android/http-debug/${HttpDebugPackagePolicy.versionCode(installed)}" in revoked) {
            try { HttpDebug.stop() }
            catch (_: Exception) { HttpDebug.release(); runCatching { RuntimeBridge.control?.restart() } }
        }
        withContext(Dispatchers.IO) { mutable.value = mutable.value.copy(cached = cachedPackages()) }
        }
    }

    suspend fun prepareInstall(release: PluginRelease): File = operations.withLock {
        val catalog = requireNotNull(mutable.value.catalog) { "请先读取已签名目录" }
        require(catalog.fresh()) { "目录已过期，请先刷新" }
        require(release in catalog.releases && compatible(release)) { "此插件不兼容或已撤销" }
        val installedBuild = HttpDebugPackagePolicy.installed(context)?.let(HttpDebugPackagePolicy::versionCode)
        require(installedBuild == null || release.build >= installedBuild) { "较旧版本需要通过缓存恢复并先卸载当前插件" }
        mutable.value = mutable.value.copy(busy = true, received = 0, total = release.bytes, error = "")
        try { withContext(Dispatchers.IO) {
            val folder = File(cache, "${release.build}-${release.sha256}").apply { mkdirs() }
            val part = File(folder, "download.part")
            try {
                http.newCall(Request.Builder().url(release.url).header("User-Agent", "sb-easy-android/plugins").build()).execute().use { response ->
                    require(response.isSuccessful) { "插件下载失败：HTTP ${response.code}" }
                    val body = requireNotNull(response.body)
                    require(body.contentLength() == -1L || body.contentLength() == release.bytes) { "插件下载大小与目录不符" }
                    var count = 0L
                    body.byteStream().use { input -> part.outputStream().use { output ->
                        val buffer = ByteArray(65536)
                        while (true) {
                            currentCoroutineContext().ensureActive()
                            val amount = input.read(buffer); if (amount < 0) break
                            count += amount; require(count <= release.bytes) { "插件下载超过签名目录大小" }
                            output.write(buffer, 0, amount)
                            mutable.value = mutable.value.copy(received = count)
                        }
                        output.fd.sync()
                    } }
                    require(count == release.bytes) { "插件下载不完整" }
                }
                HttpDebugPackagePolicy.inspect(context, part, hostVersion, release)
                require(catalog.fresh()) { "目录在下载期间过期，请刷新后重试" }
                backupInstalled(catalog, release)
                val target = File(folder, "plugin.apk")
                check(part.renameTo(target)) { "无法提交已验证的插件文件" }
                writeReceipt(folder, catalog.envelope)
                trimCache(release.build)
                mutable.value = mutable.value.copy(cached = cachedPackages())
                target
            } finally { part.delete() }
        } } catch (failure: Exception) { mutable.value = mutable.value.copy(error = failure.message.orEmpty()); throw failure }
        finally { mutable.value = mutable.value.copy(busy = false) }
    }

    /** Recovery may use an expired receipt for code previously verified on this device. */
    suspend fun prepareCached(cached: CachedPlugin): File = operations.withLock { withContext(Dispatchers.IO) {
        requireNotRevoked(cached.release.build)
        val verified = cachedPackages().firstOrNull { it.file.canonicalPath == cached.file.canonicalPath && it.release == cached.release }
        requireNotNull(verified) { "缓存记录已变化或签名不再受信任" }
        require(compatible(verified.release)) { "缓存版本与当前应用/核心不兼容" }
        HttpDebugPackagePolicy.inspect(context, verified.file, hostVersion, verified.release)
        verified.file
    } }

    private fun backupInstalled(catalog: VerifiedPluginCatalog, incoming: PluginRelease) {
        val installed = HttpDebugPackagePolicy.installed(context) ?: return
        val build = HttpDebugPackagePolicy.versionCode(installed)
        if (build == incoming.build) return
        // Revoked or incompatible legacy code cannot be a recovery candidate.
        if (runCatching { HttpDebugPackagePolicy.requireInstalled(context, hostVersion) }.isFailure) return
        val path = requireNotNull(installed.applicationInfo?.sourceDir) { "无法定位已安装插件" }
        require(installed.applicationInfo?.splitSourceDirs.isNullOrEmpty()) { "当前分拆插件不能安全备份，请先通过系统卸载" }
        val source = File(path)
        val actual = HttpDebugPackagePolicy.inspect(context, source, hostVersion)
        val release = catalog.releases.firstOrNull { it.id == "http-debug" && it.platform == "android" && it.build == build &&
            it.sha256 == actual.sha256 && it.signerSha256 == actual.signer && it.bytes == actual.bytes && it.abi in actual.abis }
            ?: mutable.value.cached.firstOrNull { it.release.build == build && it.release.sha256 == actual.sha256 }?.release
        requireNotNull(release) { "当前插件没有受目录签名的恢复版本，请先取得包含当前版本的可信目录" }
        if (mutable.value.cached.any { it.release == release && runCatching { HttpDebugPackagePolicy.inspect(context, it.file, hostVersion, release) }.isSuccess }) return
        val folder = File(cache, "$build-${actual.sha256}").apply { mkdirs() }
        val part = File(folder, "backup.part")
        try {
            source.copyTo(part, overwrite = true)
            HttpDebugPackagePolicy.inspect(context, part, hostVersion, release)
            check(part.renameTo(File(folder, "plugin.apk"))) { "无法保存旧插件恢复文件" }
            writeReceipt(folder, catalog.envelope)
        } finally { part.delete() }
    }

    private fun writeReceipt(folder: File, envelope: String) {
        val receipt = AtomicFile(File(folder, "receipt.json")); val output = receipt.startWrite()
        try { output.write(envelope.toByteArray(Charsets.UTF_8)); receipt.finishWrite(output) }
        catch (failure: Throwable) { receipt.failWrite(output); throw failure }
    }

    private fun cachedPackages(): List<CachedPlugin> = cache.listFiles().orEmpty().filter { it.isDirectory && it.name.matches(Regex("[0-9]{1,10}-[0-9a-f]{64}")) }.mapNotNull { folder ->
        runCatching {
            val receipt = File(folder, "receipt.json")
            require(receipt.length() in 1..PluginCatalog.MAX_ENVELOPE.toLong())
            val catalog = PluginCatalog.verify(receipt.readText(), keys, requireFresh = false)
            val apk = File(folder, "plugin.apk")
            val release = catalog.releases.single { "${it.build}-${it.sha256}" == folder.name && it.platform == "android" && it.id == "http-debug" }
            require(apk.isFile && apk.length() == release.bytes && release.revocationKey !in mutable.value.revoked)
            CachedPlugin(release, apk)
        }.getOrNull()
    }.sortedByDescending { it.release.build }.take(3)

    private fun trimCache(incoming: Long) {
        val installed = HttpDebugPackagePolicy.installed(context)?.let(HttpDebugPackagePolicy::versionCode)
        val records = cachedPackages()
        val retained = (records.filter { it.release.build == incoming || it.release.build == installed } + records)
            .distinctBy { requireNotNull(it.file.parentFile).path }.take(2).map { requireNotNull(it.file.parentFile).name }.toSet()
        cache.listFiles().orEmpty().filter { it.isDirectory && it.name.matches(Regex("[0-9]{1,10}-[0-9a-f]{64}")) && it.name !in retained }.forEach { directory ->
            // Only known cache files are removed; unexpected content is left untouched.
            listOf("plugin.apk", "receipt.json", "receipt.json.bak", "download.part", "backup.part").forEach { File(directory, it).delete() }
            directory.delete()
        }
    }
}
