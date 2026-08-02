package io.sbeasy.android.core

import java.net.URI
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import okhttp3.OkHttpClient
import okhttp3.Request

class RouteTester {
    private val client = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .callTimeout(12, TimeUnit.SECONDS)
        .followRedirects(true)
        .build()

    suspend fun test(raw: String): RouteTestResult {
        val uri = URI(raw.trim())
        require(uri.scheme == "http" || uri.scheme == "https") { "仅支持 HTTP/HTTPS URL" }
        require(uri.host != null && uri.userInfo == null) { "URL 格式无效，且不能包含账号信息" }
        val safeUrl = URI(uri.scheme, null, uri.host, uri.port, uri.path.ifEmpty { "/" }, null, null).toString()
        val startedAt = System.currentTimeMillis()
        var status: Int? = null
        var requestError: String? = null
        withContext(Dispatchers.IO) {
            runCatching {
                val request = Request.Builder().url(uri.toString()).header("Range", "bytes=0-0").get().build()
                client.newCall(request).execute().use { status = it.code }
            }.onFailure { requestError = it.message ?: it.javaClass.simpleName }
        }

        var connection: ConnectionSnapshot? = null
        for (attempt in 0 until 15) {
            connection = RuntimeObservability.connections.value.firstOrNull {
                it.createdAt >= startedAt - 1_500 &&
                    (it.domain.equals(uri.host, ignoreCase = true) || it.destination.startsWith(uri.host))
            }
            if (connection != null) break
            delay(100)
        }
        val matched = connection
        val outbound = matched?.outbound.orEmpty()
        val outboundType = matched?.outboundType.orEmpty()
        val decision = when {
            outbound.equals("block", true) || outboundType.equals("block", true) -> RouteDecision.BLOCK
            outbound.equals("direct", true) || outboundType.equals("direct", true) -> RouteDecision.DIRECT
            outbound.isNotBlank() || matched?.chain?.isNotEmpty() == true -> RouteDecision.PROXY
            else -> RouteDecision.UNKNOWN
        }
        val error = when {
            decision == RouteDecision.BLOCK -> "规则阻止了该请求"
            matched == null && requestError != null -> requestError
            matched == null -> "请求已完成，但没有捕获到对应的 libbox 连接"
            else -> requestError
        }
        return RouteTestResult(
            url = safeUrl,
            decision = decision,
            outbound = outbound,
            rule = matched?.rule.orEmpty(),
            chain = matched?.chain.orEmpty(),
            latencyMillis = System.currentTimeMillis() - startedAt,
            httpStatus = status,
            error = error,
        )
    }
}
