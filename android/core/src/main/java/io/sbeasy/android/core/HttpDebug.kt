package io.sbeasy.android.core

import android.content.*
import android.content.pm.PackageManager
import android.os.*
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject

data class HttpDebugState(
    val phase: String = "stopped", val error: String = "", val url: String = "",
    val attached: Boolean = false, val domains: List<String> = emptyList(), val caFingerprint: String = "",
)

/** Session secrets exist only in memory and signature-protected plugin IPC. */
object HttpDebug {
    const val PACKAGE = "io.sbeasy.httpdebug"
    const val MIN_PLUGIN_VERSION = 2L
    private val mutable = MutableStateFlow(HttpDebugState())
    val state = mutable.asStateFlow()
    private val operations = Mutex()
    private val main by lazy { Handler(Looper.getMainLooper()) }
    private val recovery by lazy { CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate) }
    @Volatile private var remote: Messenger? = null
    @Volatile private var binding: ServiceConnection? = null
    private var context: Context? = null
    private val pending = ConcurrentHashMap<Int, CompletableDeferred<JSONObject>>()
    private var sequence = 0
    private var monitorJob: Job? = null
    private var authorityFingerprints = emptySet<String>()
    @Volatile private var password = ""
    @Volatile private var domains = emptyList<String>()
    @Volatile private var attached = false
    private val replies by lazy { Messenger(Handler(Looper.getMainLooper()) { message ->
        pending.remove(message.what)?.let { result ->
            val error = message.data.getString("error")
            if (error != null) result.completeExceptionally(IllegalStateException(error))
            else runCatching { JSONObject(message.data.getString("result") ?: "{}") }
                .onSuccess(result::complete).onFailure(result::completeExceptionally)
        }; true
    }) }

    fun initialize(owner: Context) {
        context = owner.applicationContext
        authorityFingerprints = preferences().getStringSet("ca_fingerprints", emptySet()).orEmpty().toSet() +
            listOfNotNull(preferences().getString("ca_fingerprint", null)?.takeIf(String::isNotBlank))
        mutable.value = mutable.value.copy(caFingerprint = authorityFingerprints.sorted().joinToString("\n"))
    }
    private fun preferences() = requireNotNull(context).getSharedPreferences("http_debug", Context.MODE_PRIVATE)
    @Suppress("DEPRECATION")
    fun installed(owner: Context): Boolean = runCatching {
        HttpDebugPackagePolicy.requireInstalled(owner, PluginTrustStore.hostVersion)
        true
    }.getOrDefault(false)

    private suspend fun call(method: String): JSONObject = withContext(Dispatchers.Main) {
        val peer = requireNotNull(remote) { "调试插件未连接" }
        val id = ++sequence
        val result = CompletableDeferred<JSONObject>()
        pending[id] = result
        try {
            peer.send(Message.obtain(null, id).apply { replyTo = replies; data = Bundle().apply { putString("method", method) } })
            withTimeout(30_000) { result.await() }
        } finally { pending.remove(id) }
    }

    private suspend fun connect(owner: Context) {
        CaptureSession.requireEnabled()
        require(installed(owner)) { "请先安装与主应用签名匹配的 1.0.1 或更新版调试插件" }
        check(binding == null) { "已有调试会话，请先停止" }
        context = owner.applicationContext
        val ready = CompletableDeferred<Unit>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                if (binding !== this) return
                remote = Messenger(service)
                ready.complete(Unit)
            }
            override fun onServiceDisconnected(name: ComponentName) {
                if (binding !== this) return
                remote = null
                pending.values.forEach { it.completeExceptionally(IllegalStateException("调试插件已断开")) }
                pending.clear()
                mutable.value = mutable.value.copy(phase = "failed", error = "引擎已停止，正在恢复普通分流")
                recovery.launch {
                    runCatching { stop() }.onSuccess {
                        mutable.value = mutable.value.copy(error = "调试插件已断开，已恢复普通分流")
                    }.onFailure {
                        mutable.value = mutable.value.copy(error = "普通分流恢复失败，请断开并重新连接 VPN")
                    }
                }
            }
            override fun onBindingDied(name: ComponentName) = onServiceDisconnected(name)
            override fun onNullBinding(name: ComponentName) { ready.completeExceptionally(IllegalStateException("无法连接调试插件")) }
        }
        binding = connection
        check(context!!.bindService(Intent().setComponent(ComponentName(PACKAGE, "$PACKAGE.EngineService")), connection, Context.BIND_AUTO_CREATE)) {
            "无法绑定调试插件"
        }
        withTimeout(15_000) { ready.await() }
    }

    suspend fun start(owner: Context) = operations.withLock { withContext(Dispatchers.Main) {
        CaptureSession.requireEnabled()
        require(RuntimeBridge.control != null) { "请先连接 VPN" }
        try {
            attached = false
            domains = emptyList()
            connect(owner)
            mutable.value = mutable.value.copy(phase = "starting", error = "")
            call("start")
            withTimeout(30_000) {
                while (true) {
                    refresh()
                    if (state.value.phase == "running") break
                    check(state.value.phase != "failed") { state.value.error }
                    delay(300)
                }
            }
            monitorJob = recovery.launch {
                while (isActive && binding != null) {
                    delay(2000)
                    try {
                        refresh()
                        if (state.value.phase != "running") {
                            val failure = state.value.error.ifBlank { "调试引擎已停止" }
                            stop(); mutable.value = mutable.value.copy(error = failure); break
                        }
                    } catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { runCatching { stop() }; break }
                }
            }
        } catch (error: Throwable) { release(); throw error }
    } }

    suspend fun refresh() {
        if (remote == null) return
        val result = call("snapshot")
        check(result.optInt("protocol_version") == HttpDebugPackagePolicy.HOST_API) { "调试插件控制协议不兼容" }
        password = result.optString("password")
        val url = result.optString("url")
        require(url.isEmpty() || url.matches(Regex("http://127\\.0\\.0\\.1:17991/\\?token=[0-9a-f]{64}"))) { "插件返回了无效的本机地址" }
        mutable.value = mutable.value.copy(phase = result.optString("phase"), error = result.optString("error"), url = url,
            attached = attached, domains = domains)
    }

    suspend fun attach(text: String) = operations.withLock {
        CaptureSession.requireEnabled()
        check(state.value.phase == "running" && !attached) { "请先启动调试引擎" }
        val nextDomains = HttpDebugRouting.normalize(text)
        val config = requireNotNull(CoreGraph.repository.activeConfig())
        HttpDebugRouting.apply(config.content, nextDomains, password)
        requireNotNull(RuntimeBridge.control) { "VPN 未运行" }
        CoreGraph.repository.updateRuntimeOverlay(
            requireRunning = true,
            update = { domains = nextDomains; attached = true },
            rollback = { attached = false; domains = emptyList() },
        )
        mutable.value = mutable.value.copy(attached = true, domains = domains)
    }

    suspend fun stop() = operations.withLock {
        if (attached) CoreGraph.repository.updateRuntimeOverlay(
            update = { attached = false }, rollback = { attached = true },
        )
        if (remote != null) runCatching { call("stop") }
        release()
    }

    suspend fun clearLocalAuthority(owner: Context) {
        stop()
        operations.withLock { withContext(Dispatchers.Main) {
            try { connect(owner); call("clear"); } finally { release() }
        } }
    }

    fun overlay(content: String): String = if (attached && CaptureSession.enabled.value && state.value.phase == "running" && context?.let(::installed) == true)
        HttpDebugRouting.apply(content, domains, password) else content

    suspend fun certificate(): ByteArray = operations.withLock {
        CaptureSession.requireEnabled()
        val hex = call("certificate").getString("der")
        require(hex.length in 2..32768 && hex.length % 2 == 0 && hex.matches(Regex("[0-9a-f]+")))
        val der = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()).verify(
            CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()).publicKey)
        val fingerprint = fingerprint(der)
        val next = authorityFingerprints + fingerprint
        check(preferences().edit().putStringSet("ca_fingerprints", next).remove("ca_fingerprint").commit()) { "证书清理提醒保存失败" }
        authorityFingerprints = next
        mutable.value = mutable.value.copy(caFingerprint = next.sorted().joinToString("\n"))
        der
    }

    /** Android does not allow an ordinary app to remove user trust anchors. Verify after Settings. */
    suspend fun verifyCertificateRemoved() = operations.withLock { withContext(Dispatchers.IO) {
        val wanted = authorityFingerprints
        if (wanted.isEmpty()) return@withContext
        val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        check(store.aliases().toList().none { alias -> store.getCertificate(alias)?.encoded?.let(::fingerprint) in wanted }) {
            "系统仍信任至少一个调试 CA，请先在安全设置中移除"
        }
        check(preferences().edit().remove("ca_fingerprint").remove("ca_fingerprints").commit()) { "无法清除证书提醒" }
        authorityFingerprints = emptySet()
        mutable.value = mutable.value.copy(caFingerprint = "")
    } }

    private fun fingerprint(der: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(der).joinToString(":") { "%02X".format(it) }

    fun release() {
        monitorJob?.cancel()
        monitorJob = null
        attached = false
        password = ""
        domains = emptyList()
        mutable.value = HttpDebugState(caFingerprint = mutable.value.caFingerprint)
        val oldBinding = binding
        val oldContext = context
        val oldRemote = remote
        binding = null
        remote = null
        pending.entries.toList().forEach { (id, task) -> if (pending.remove(id, task)) task.cancel() }
        if (oldBinding != null) main.post {
            var unbound = false
            fun unbind() { if (!unbound) { unbound = true; runCatching { oldContext?.unbindService(oldBinding) } } }
            if (oldRemote == null) unbind() else {
                // Releasing the VPN cannot suspend. Request key cleanup on the old
                // binding before unbinding; capture routes and host secrets are gone.
                val reply = Messenger(Handler(Looper.getMainLooper()) { unbind(); true })
                runCatching { oldRemote.send(Message.obtain(null, 0).apply {
                    replyTo = reply; data = Bundle().apply { putString("method", "clear") }
                }) }.onFailure { unbind() }
                main.postDelayed({ unbind() }, 5000)
            }
        }
    }
}
