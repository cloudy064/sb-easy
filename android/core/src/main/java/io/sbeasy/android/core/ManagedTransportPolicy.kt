package io.sbeasy.android.core

import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.util.concurrent.TimeUnit
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

/** A local HTTP exception is explicit, bound to this enrollment, and never resolved through DNS. */
object ManagedTransportPolicy {
    fun normalizeServer(raw: String, allowInsecureLocalHttp: Boolean = false): String {
        val value = raw.trim().trimEnd('/')
        require(value.length in 1..4096 && value.none { it.isWhitespace() || it.code < 32 } && '\\' !in value) { "服务器地址格式无效" }
        val uri = runCatching { URI(value) }.getOrNull()
        val url = value.toHttpUrlOrNull()
        require(uri != null && uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null && url != null) { "服务器地址不能包含账户、查询参数或片段" }
        require(url.isHttps || (allowInsecureLocalHttp && url.scheme == "http" && localLiteral(url.host))) {
            "中心默认要求 HTTPS；仅可明确允许使用内网或回环 IP 的局域网 HTTP 测试中心"
        }
        return url.toString().trimEnd('/')
    }

    fun canAllowLocalHttp(raw: String): Boolean = runCatching {
        val server = normalizeServer(raw, true)
        server.startsWith("http://")
    }.getOrDefault(false)

    fun returnedServer(requested: String, returned: String, allowInsecureLocalHttp: Boolean): String {
        val expected = normalizeServer(requested, allowInsecureLocalHttp)
        val actual = normalizeServer(returned, allowInsecureLocalHttp)
        require(actual == expected) { "中心返回了不同的服务地址；请修正中心公开地址并重新生成注册链接，不会把设备令牌发送到该地址" }
        return expected
    }

    private fun localLiteral(host: String): Boolean {
        if (':' in host) {
            if (host.any { it !in "0123456789abcdefABCDEF:." }) return false
            val address = runCatching { InetAddress.getByName(host) }.getOrNull() as? Inet6Address ?: return false
            val bytes = address.address
            return address.isLoopbackAddress || (bytes[0].toInt() and 0xfe) == 0xfc
        }
        val parts = host.split('.')
        if (parts.size != 4 || parts.any { !it.matches(Regex("0|[1-9][0-9]{0,2}")) || it.toInt() > 255 }) return false
        val numbers = parts.map(String::toInt)
        return numbers[0] == 127 || numbers[0] == 10 ||
            (numbers[0] == 172 && numbers[1] in 16..31) || (numbers[0] == 192 && numbers[1] == 168)
    }
}

/** Shared by enrollment, authenticated API calls, physical-network retries and capture uploads. */
class ManagedControlTransport(transport: OkHttpClient = OkHttpClient.Builder()
    .connectTimeout(10, TimeUnit.SECONDS).readTimeout(20, TimeUnit.SECONDS)
    .writeTimeout(20, TimeUnit.SECONDS).callTimeout(30, TimeUnit.SECONDS).retryOnConnectionFailure(true).build()) {
    val client: OkHttpClient = transport.newBuilder().followRedirects(false).followSslRedirects(false).build()
    private data class LocalHttpAuthorization(val allowed: Boolean)

    fun request(server: String, path: String, allowInsecureLocalHttp: Boolean = false): Request.Builder {
        require(path.startsWith("/api/") && '?' !in path && '#' !in path) { "无效的中心 API 路径" }
        val base = ManagedTransportPolicy.normalizeServer(server, allowInsecureLocalHttp)
        return Request.Builder().url(base + path).tag(LocalHttpAuthorization::class.java, LocalHttpAuthorization(allowInsecureLocalHttp))
    }

    fun execute(request: Request, routeClient: OkHttpClient = client): Response {
        ManagedTransportPolicy.normalizeServer(request.url.toString(), request.tag(LocalHttpAuthorization::class.java)?.allowed == true)
        require(!routeClient.followRedirects && !routeClient.followSslRedirects) { "中心请求不能自动跟随重定向" }
        val response = routeClient.newCall(request).execute()
        if (response.code in 300..399 && response.code != 304) {
            response.close()
            throw IllegalArgumentException("中心返回了重定向，已拒绝转发注册信息或设备令牌；请使用最终 HTTPS 地址重新配置中心")
        }
        return response
    }
}
