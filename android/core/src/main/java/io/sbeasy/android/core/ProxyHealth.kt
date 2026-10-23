package io.sbeasy.android.core

import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

enum class AutomaticSelection { FAILOVER, FASTEST }

data class HealthPolicy(
    val enabled: Boolean = true,
    val probeUrl: String = "https://www.gstatic.com/generate_204",
    val intervalSeconds: Int = 180,
    val timeoutMillis: Int = 5000,
    val toleranceMillis: Int = 100,
    val selection: AutomaticSelection = AutomaticSelection.FAILOVER,
) {
    fun validate() {
        val url = probeUrl.toHttpUrlOrNull()
        require(probeUrl.length <= 2048 && url?.isHttps == true && url.username.isEmpty() && url.password.isEmpty() && url.fragment == null) {
            "探测网址须为 HTTPS，且不能含用户名、密码或片段"
        }
        require(intervalSeconds in 30..86400) { "探测间隔须为 30–86400 秒" }
        // Both sing-box 1.13 and 1.14 parse this Clash API parameter as a signed 16-bit integer.
        require(timeoutMillis in 500..30000) { "探测超时须为 500–30000 毫秒" }
        require(toleranceMillis in 0..10000) { "延迟容差须为 0–10000 毫秒" }
    }
    fun json(): JSONObject = JSONObject().put("enabled", enabled).put("probe_url", probeUrl)
        .put("interval_seconds", intervalSeconds).put("timeout_millis", timeoutMillis)
        .put("tolerance_millis", toleranceMillis).put("selection", selection.name.lowercase())
    companion object {
        fun decode(json: JSONObject?): HealthPolicy = if (json == null) HealthPolicy() else HealthPolicy(
            json.optBoolean("enabled", true), json.optString("probe_url", "https://www.gstatic.com/generate_204"),
            json.optInt("interval_seconds", 180), json.optInt("timeout_millis", 5000), json.optInt("tolerance_millis", 100),
            when (json.optString("selection", "failover")) { "failover" -> AutomaticSelection.FAILOVER; "fastest" -> AutomaticSelection.FASTEST; else -> error("无效的自动切换策略") },
        ).also { it.validate() }
    }
}

data class NodeHealthResult(val tag: String, val latencyMillis: Int?, val error: String? = null, val checkedAtMillis: Long = System.currentTimeMillis()) {
    val healthy: Boolean get() = latencyMillis != null && latencyMillis > 0 && error == null
}
data class HealthSnapshot(
    val checking: Boolean = false,
    val checkedAtMillis: Long = 0,
    val results: List<NodeHealthResult> = emptyList(),
    val selected: Map<String, String> = emptyMap(),
    val warnings: List<String> = emptyList(),
)

object HealthSelection {
    /** Null means every allowed candidate failed. It never means direct or an unlisted node. */
    fun choose(current: String?, candidates: List<String>, results: List<NodeHealthResult>, policy: HealthPolicy): String? {
        val byTag = results.associateBy { it.tag }
        val healthy = candidates.distinct().mapNotNull { tag -> byTag[tag]?.takeIf { it.healthy && it.latencyMillis!! <= policy.timeoutMillis } }
        val fastest = healthy.minByOrNull { it.latencyMillis!! } ?: return null
        val retained = healthy.firstOrNull { it.tag == current }
        if (retained == null) return fastest.tag
        if (policy.selection == AutomaticSelection.FAILOVER) return retained.tag
        return if (retained.latencyMillis!! - fastest.latencyMillis!! > policy.toleranceMillis) fastest.tag else retained.tag
    }
}

/** A per-runtime local controller; neither its secret nor listen port enters persisted/displayed config. */
class LoopbackHealthApi internal constructor(val port: Int, private val secret: String) {
    init { require(port in 1..65535 && secret.length >= 32) }
    private val baseUrl = "http://127.0.0.1:$port".toHttpUrl()
    private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
        .retryOnConnectionFailure(false).connectTimeout(1, TimeUnit.SECONDS).build()

    fun runtimeConfig(content: String): String {
        val root = JSONObject(content)
        val experimental = root.optJSONObject("experimental") ?: JSONObject().also { root.put("experimental", it) }
        experimental.put("clash_api", JSONObject().put("external_controller", "127.0.0.1:$port").put("secret", secret)
            .put("default_mode", "Rule").put("access_control_allow_origin", JSONArray(listOf("http://127.0.0.1"))))
        return root.toString()
    }

    suspend fun probe(tag: String, url: String, timeoutMillis: Int): NodeHealthResult {
        HealthPolicy(probeUrl = url, timeoutMillis = timeoutMillis).validate()
        require(tag.isNotBlank())
        val target = baseUrl.newBuilder().addPathSegment("proxies").addPathSegment(tag).addPathSegment("delay")
            .addQueryParameter("url", url).addQueryParameter("timeout", timeoutMillis.toString()).build()
        val call = client.newBuilder().callTimeout(timeoutMillis + 2000L, TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMillis + 2000L, TimeUnit.MILLISECONDS).build().newCall(
                Request.Builder().url(target).header("Authorization", "Bearer $secret").get().build(),
            )
        return try {
            val delay = withTimeout(timeoutMillis.toLong()) { call.awaitDelay() }
            if (delay <= 0 || delay > timeoutMillis) NodeHealthResult(tag, null, "探测超时或无有效延迟") else NodeHealthResult(tag, delay)
        } catch (_: TimeoutCancellationException) {
            currentCoroutineContext().ensureActive()
            NodeHealthResult(tag, null, "探测超过 ${timeoutMillis}ms 截止时间")
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            // API response bodies and target URL query strings never enter diagnostics.
            NodeHealthResult(tag, null, "节点不可达、探测失败或超时")
        }
    }

    private suspend fun Call.awaitDelay(): Int = suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { cancel() }
        enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) { if (continuation.isActive) continuation.resumeWithException(e) }
            override fun onResponse(call: Call, response: Response) {
                val result = runCatching { response.use {
                    require(it.isSuccessful)
                    val body = requireNotNull(it.body)
                    require(body.contentLength() <= 4096)
                    val source = body.source()
                    require(!source.request(4097))
                    JSONObject(source.readUtf8()).getInt("delay")
                } }
                if (continuation.isActive) result.fold(continuation::resume, continuation::resumeWithException)
            }
        })
    }

    companion object {
        fun create(): LoopbackHealthApi {
            val port = ServerSocket(0, 0, InetAddress.getByName("127.0.0.1")).use { it.localPort }
            val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
            return LoopbackHealthApi(port, bytes.toByteString().base64Url())
        }
    }
}
