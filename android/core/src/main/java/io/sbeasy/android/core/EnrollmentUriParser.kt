package io.sbeasy.android.core

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

object EnrollmentUriParser {
    fun parse(raw: String, allowInsecureLocalHttp: Boolean = false): Pair<String, String> {
        val value = clean(raw)
        val uri = runCatching { URI(value) }
            .getOrElse { throw IllegalArgumentException("不是有效的 sb-easy 注册链接") }
        require(uri.scheme.equals("sbeasy", ignoreCase = true) &&
            uri.host.equals("enroll", ignoreCase = true)) {
            "不是有效的 sb-easy 注册链接"
        }
        val parameters = parseQuery(uri.rawQuery)
        val server = normalizeServer(parameters["server"]?.singleOrNull()
            ?: throw IllegalArgumentException("注册链接缺少服务器地址"), allowInsecureLocalHttp)
        val code = parameters["code"]?.singleOrNull()
            ?: throw IllegalArgumentException("注册链接缺少注册码")
        require(ENROLLMENT_CODE.matches(code)) { "注册码格式无效" }
        return server to code.lowercase()
    }

    /** Inspection shows an eligible local HTTP link without authorizing a request. */
    fun inspect(raw: String): Pair<String, String> = parse(raw, allowInsecureLocalHttp = true)

    fun normalizeServer(raw: String, allowInsecureLocalHttp: Boolean = false): String =
        ManagedTransportPolicy.normalizeServer(raw, allowInsecureLocalHttp)

    private fun clean(raw: String): String {
        var value = raw.replace("\u0000", "").trim()
        if (value.length >= 2 &&
            ((value.first() == '"' && value.last() == '"') ||
                (value.first() == '\'' && value.last() == '\''))
        ) {
            value = value.substring(1, value.lastIndex).trim()
        }
        if (value.startsWith("URL:", ignoreCase = true)) {
            value = value.substring(4).trim()
        }
        return value
    }

    private fun parseQuery(rawQuery: String?): Map<String, List<String>> {
        require(!rawQuery.isNullOrBlank()) { "注册链接缺少参数" }
        return rawQuery.split('&').mapNotNull { item ->
            if (item.isBlank()) return@mapNotNull null
            val separator = item.indexOf('=')
            val key = decode(if (separator < 0) item else item.substring(0, separator))
            val value = decode(if (separator < 0) "" else item.substring(separator + 1))
            key to value
        }.groupBy({ it.first }, { it.second })
    }

    private fun decode(value: String): String =
        runCatching { URLDecoder.decode(value, StandardCharsets.UTF_8.name()) }
            .getOrElse { throw IllegalArgumentException("注册链接参数编码无效") }

    private val ENROLLMENT_CODE = Regex("[0-9a-fA-F]{64}")
}
