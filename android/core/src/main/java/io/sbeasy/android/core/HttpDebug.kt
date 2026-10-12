package io.sbeasy.android.core

import android.content.*
import android.content.pm.PackageManager
import android.os.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

data class HttpDebugState(val phase: String = "stopped", val error: String = "", val url: String = "", val attached: Boolean = false, val domains: List<String> = emptyList())

/** Independent, signature-protected plugin; capture secrets never enter managed config storage. */
object HttpDebug {
    const val PACKAGE = "io.sbeasy.httpdebug"
    private val mutable = MutableStateFlow(HttpDebugState())
    val state = mutable.asStateFlow()
    private val main = Handler(Looper.getMainLooper())
    private var remote: Messenger? = null
    private var binding: ServiceConnection? = null
    private var context: Context? = null
    private val pending = mutableMapOf<Int, CompletableDeferred<JSONObject>>()
    private var sequence = 0
    @Volatile private var password = ""
    @Volatile private var domains = emptyList<String>()
    @Volatile private var attached = false
    private val replies = Messenger(Handler(Looper.getMainLooper()) { message ->
        pending.remove(message.what)?.let { result ->
            val error = message.data.getString("error")
            if (error != null) result.completeExceptionally(IllegalStateException(error))
            else runCatching { JSONObject(message.data.getString("result") ?: "{}") }
                .onSuccess(result::complete).onFailure(result::completeExceptionally)
        }; true
    })
    fun installed(context: Context): Boolean = runCatching {
        context.packageManager.getPackageInfo(PACKAGE, 0)
        context.packageManager.checkSignatures(context.packageName, PACKAGE) == PackageManager.SIGNATURE_MATCH
    }.getOrDefault(false)

    private suspend fun call(method: String): JSONObject = withContext(Dispatchers.Main) {
        val peer = requireNotNull(remote) { "抓包插件未连接" }
        val id = ++sequence; val result = CompletableDeferred<JSONObject>(); pending[id] = result
        try {
            peer.send(Message.obtain(null, id).apply { replyTo = replies; data = Bundle().apply { putString("method", method) } })
            withTimeout(30_000) { result.await() }
        } finally { pending.remove(id) }
    }
    suspend fun start(owner: Context) = withContext(Dispatchers.Main) {
        require(RuntimeBridge.control != null) { "请先连接 VPN" }
        require(installed(owner)) { "请先从扩展商店安装匹配签名的 HTTP(S) 抓包插件" }
        check(binding == null) { "已有抓包会话，请先停止" }
        context = owner.applicationContext
        val ready = CompletableDeferred<Unit>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) { remote = Messenger(service); ready.complete(Unit) }
            override fun onServiceDisconnected(name: ComponentName) {
                remote = null; mutable.value = mutable.value.copy(phase = "failed", error = "抓包引擎已停止。请停止抓包以恢复普通代理。")
                pending.values.forEach { it.completeExceptionally(IllegalStateException("抓包插件已断开")) }; pending.clear()
            }
            override fun onNullBinding(name: ComponentName) { ready.completeExceptionally(IllegalStateException("无法连接插件")) }
        }
        binding = connection
        try {
            check(context!!.bindService(Intent().setComponent(ComponentName(PACKAGE, "$PACKAGE.EngineService")), connection, Context.BIND_AUTO_CREATE))
            withTimeout(15_000) { ready.await() }
            mutable.value = HttpDebugState(phase = "starting")
            call("start")
            withTimeout(30_000) { while (true) { refresh(); if (state.value.phase == "running") break; check(state.value.phase != "failed") { state.value.error }; delay(300) } }
        } catch (error: Throwable) { release(); throw error }
    }
    suspend fun refresh() {
        if (remote == null) return
        val result = call("snapshot")
        password = result.optString("password")
        mutable.value = HttpDebugState(result.optString("phase"), result.optString("error"), result.optString("url"), attached, domains)
    }
    suspend fun attach(text: String) {
        check(state.value.phase == "running" && !attached)
        domains = HttpDebugRouting.normalize(text)
        val config = requireNotNull(CoreGraph.repository.activeConfig())
        HttpDebugRouting.apply(config.content, domains, password)
        attached = true
        try { requireNotNull(RuntimeBridge.control).applyConfiguration(config) }
        catch (error: Throwable) { attached = false; runCatching { RuntimeBridge.control?.applyConfiguration(config) }; throw error }
        mutable.value = mutable.value.copy(attached = true, domains = domains)
    }
    suspend fun stop() {
        if (attached) {
            attached = false
            try { CoreGraph.repository.activeConfig()?.let { RuntimeBridge.control?.applyConfiguration(it) } }
            catch (error: Throwable) { attached = true; throw error }
        }
        release()
    }
    fun overlay(content: String): String = if (attached) HttpDebugRouting.apply(content, domains, password) else content
    suspend fun certificate(): ByteArray {
        val hex = call("certificate").getString("der")
        require(hex.length in 2..32768 && hex.length % 2 == 0 && hex.matches(Regex("[0-9a-f]+")))
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
    fun release() {
        attached = false; password = ""; domains = emptyList(); mutable.value = HttpDebugState()
        main.post {
            binding?.let { runCatching { context?.unbindService(it) } }; binding = null; remote = null
            pending.values.forEach { it.cancel() }; pending.clear()
        }
    }
}
