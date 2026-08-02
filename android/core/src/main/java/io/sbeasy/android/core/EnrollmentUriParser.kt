package io.sbeasy.android.core

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

object EnrollmentUriParser {
    fun parse(raw: String): Pair<String, String> {
        val value = clean(raw)
        val uri = runCatching { URI(value) }
            .getOrElse { throw IllegalArgumentException("不是有效的 sb-easy 注册链接") }
        require(uri.scheme.equals("sbeasy", ignoreCase = true) &&
            uri.host.equals("enroll", ignoreCase = true)) {
            "不是有效的 sb-easy 注册链接"
        }
        val parameters = parseQuery(uri.rawQuery)
        val server = normalizeServer(parameters["server"]?.singleOrNull()
            ?: throw IllegalArgumentException("注册链接缺少服务器地址"))
        val code = parameters["code"]?.singleOrNull()
            ?: throw IllegalArgumentException("注册链接缺少注册码")
        require(ENROLLMENT_CODE.matches(code)) { "注册码格式无效" }
        return server to code.lowercase()
    }

    fun normalizeServer(raw: String): String {
        val value = raw.trim().trimEnd('/')
        val uri = runCatching { URI(value) }
            .getOrElse { throw IllegalArgumentException("服务器地址格式无效") }
        require(uri.scheme.equals("http", ignoreCase = true) ||
            uri.scheme.equals("https", ignoreCase = true)) {
            "服务器地址必须使用 HTTP 或 HTTPS"
        }
        require(uri.host != null && uri.userInfo == null && uri.query == null && uri.fragment == null) {
            "服务器地址格式无效"
        }
        return value
    }

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
