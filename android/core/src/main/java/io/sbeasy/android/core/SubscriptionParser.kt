package io.sbeasy.android.core

import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okio.ByteString.Companion.decodeBase64
import org.json.JSONArray
import org.json.JSONObject
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

/** Reports never include source text, credentials or subscription URLs. */
data class SubscriptionIssue(val index: Int, val reason: String)
data class SubscriptionImport(val nodes: List<JSONObject>, val issues: List<SubscriptionIssue>, val format: String) {
    val summary: String get() = "${nodes.size} 个节点已导入，${issues.size} 项已跳过（$format）；只导入节点，本机分流独立保存"
}
data class SubscriptionQuota(val upload: Long? = null, val download: Long? = null, val total: Long? = null, val expire: Long? = null) {
    val remaining: Long? get() = total?.let { capacity ->
        val afterUpload = capacity - (upload ?: 0).coerceAtMost(capacity)
        afterUpload - (download ?: 0).coerceAtMost(afterUpload)
    }
    fun expired(nowMillis: Long) = expire?.let { it <= nowMillis / 1000 } ?: false
    fun json(): JSONObject = JSONObject().put("upload", upload).put("download", download).put("total", total).put("expire", expire)
    companion object {
        fun parse(header: String?): SubscriptionQuota {
            val values = header.orEmpty().split(';').mapNotNull { item ->
                val parts = item.trim().split('=', limit = 2)
                if (parts.size != 2) null else parts[1].trim().toLongOrNull()?.takeIf { it >= 0 }?.let { parts[0].trim().lowercase() to it }
            }.toMap()
            return SubscriptionQuota(values["upload"], values["download"], values["total"], values["expire"]?.takeIf { it in 1..Long.MAX_VALUE / 1000 })
        }
        fun fromJson(json: JSONObject) = SubscriptionQuota(
            if (json.has("upload")) json.getLong("upload") else null,
            if (json.has("download")) json.getLong("download") else null,
            if (json.has("total")) json.getLong("total") else null,
            if (json.has("expire")) json.getLong("expire") else null,
        )
    }
}

object SubscriptionParser {
    const val MAX_BYTES = 1024 * 1024
    const val MAX_NODES = 512
    private val protocols = setOf("shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic", "http", "socks")
    private val infrastructure = setOf("direct", "block", "dns", "selector", "urltest")

    fun parse(body: String): SubscriptionImport {
        require(body.isNotBlank() && body.toByteArray().size <= MAX_BYTES) { "订阅为空或超过 1 MB" }
        val content = body.trim().removePrefix("\uFEFF")
        val rows: List<Any?>
        val convert: (Any?) -> JSONObject
        val format: String
        try {
            when {
                content.startsWith('{') || content.startsWith('[') -> {
                    val array = if (content.startsWith('[')) JSONArray(content) else JSONObject(content).optJSONArray("outbounds") ?: error("missing outbounds")
                    rows = (0 until array.length()).map { array.get(it) }
                    convert = { JSONObject((it as JSONObject).toString()) }
                    format = "sing-box JSON"
                }
                Regex("(?m)^\\s*proxies\\s*:").containsMatchIn(content) -> {
                    val options = LoaderOptions().apply {
                        codePointLimit = MAX_BYTES; maxAliasesForCollections = 20; nestingDepthLimit = 20; isAllowDuplicateKeys = false
                    }
                    val root = Yaml(SafeConstructor(options)).load<Any>(content) as? Map<*, *> ?: error("missing object")
                    rows = root["proxies"] as? List<*> ?: error("missing proxies")
                    convert = { clash(JSONObject(it as Map<*, *>)) }
                    format = "Clash YAML"
                }
                else -> {
                    val decoded = if (content.contains("://")) content else decode64(content)
                    rows = decoded.lines().map(String::trim).filter { it.isNotEmpty() && !it.startsWith('#') }
                    convert = { uri(it as String) }
                    format = if (content.contains("://")) "分享链接" else "Base64"
                }
            }
        } catch (_: Exception) {
            throw IllegalArgumentException("无法解析订阅：支持 Clash YAML、sing-box JSON、分享链接及 Base64 订阅")
        }
        require(rows.isNotEmpty() && rows.size <= MAX_NODES + 64) { "订阅须包含 1–$MAX_NODES 个代理节点" }
        val issues = mutableListOf<SubscriptionIssue>()
        val names = mutableSetOf<String>()
        val nodes = rows.mapIndexedNotNull { index, row ->
            try {
                val node = convert(row)
                if (node.optString("type") in infrastructure) {
                    issues.add(SubscriptionIssue(index + 1, "分组、直连或 DNS 出站由本机配置管理")); null
                } else {
                    validate(node)
                    val original = node.optString("tag").ifBlank { "节点 ${index + 1}" }.take(64)
                    var tag = original
                    var suffix = 2
                    while (!names.add(tag)) tag = "${original.take(56)} (${suffix++})"
                    node.put("tag", tag)
                }
            } catch (error: ImportError) {
                issues.add(SubscriptionIssue(index + 1, error.message.orEmpty())); null
            } catch (_: Exception) {
                issues.add(SubscriptionIssue(index + 1, "节点字段无效或缺少认证信息")); null
            }
        }
        require(nodes.isNotEmpty()) { "未找到可用节点：${issues.take(5).joinToString("；") { "第 ${it.index} 项：${it.reason}" }}" }
        require(nodes.size <= MAX_NODES) { "每个订阅最多 $MAX_NODES 个节点" }
        return SubscriptionImport(nodes, issues, format)
    }

    private class ImportError(message: String) : IllegalArgumentException(message)
    private fun supported(condition: Boolean, reason: String) { if (!condition) throw ImportError(reason) }
    private fun decode64(value: String) = value.filterNot(Char::isWhitespace).decodeBase64()?.utf8() ?: error("base64")
    private fun decode(value: String) = URLDecoder.decode(value.replace("+", "%2B"), "UTF-8")
    private fun transport(node: JSONObject, network: String, path: String, host: String) {
        when (network) {
            "", "tcp" -> Unit
            "ws" -> node.put("transport", JSONObject().put("type", "ws").put("path", path.ifBlank { "/" }).also {
                if (host.isNotBlank()) it.put("headers", JSONObject().put("Host", host))
            })
            "grpc" -> node.put("transport", JSONObject().put("type", "grpc").put("service_name", path))
            "http", "h2" -> node.put("transport", JSONObject().put("type", "http").put("path", path.ifBlank { "/" }).also {
                if (host.isNotBlank()) it.put("host", JSONArray(host.split(',')))
            })
            "httpupgrade" -> node.put("transport", JSONObject().put("type", "httpupgrade").put("path", path.ifBlank { "/" }).put("host", host))
            else -> throw ImportError("不支持此传输方式")
        }
    }
    private fun uri(raw: String): JSONObject {
        if (raw.startsWith("vmess://")) {
            val p = JSONObject(decode64(raw.substring(8)))
            val n = JSONObject().put("type", "vmess").put("tag", p.optString("ps")).put("server", p.getString("add"))
                .put("server_port", p.getInt("port")).put("uuid", p.getString("id")).put("security", p.optString("scy", "auto")).put("alter_id", p.optInt("aid"))
            supported(p.optString("type") in setOf("", "none"), "不支持 VMess TCP 伪装头")
            transport(n, p.optString("net"), p.optString("path"), p.optString("host"))
            if (p.optString("tls") == "tls") n.put("tls", JSONObject().put("enabled", true).put("server_name", p.optString("sni").ifBlank { p.optString("host").ifBlank { p.getString("add") } }))
            return n
        }
        var line = raw
        if (line.startsWith("ss://") && !line.substringBefore('#').contains('@')) {
            val value = line.substring(5)
            line = "ss://${decode64(value.substringBefore('#'))}" + if (value.contains('#')) "#${value.substringAfter('#')}" else ""
        }
        val url = URI(line)
        val type = when (url.scheme?.lowercase()) { "ss" -> "shadowsocks"; "hy2" -> "hysteria2"; "socks5" -> "socks"; "https" -> "http"; else -> url.scheme.orEmpty() }
        supported(type in protocols, "不支持此代理协议")
        val q = url.rawQuery.orEmpty().split('&').filter { it.isNotEmpty() }.associate {
            decode(it.substringBefore('=')) to decode(it.substringAfter('=', ""))
        }
        val auth = decode(url.rawUserInfo.orEmpty())
        val user = auth.substringBefore(':'); val password = auth.substringAfter(':', "")
        val host = url.host?.removeSurrounding("[", "]") ?: error("host")
        val n = JSONObject().put("type", type).put("tag", decode(url.rawFragment.orEmpty()).ifBlank { host }).put("server", host)
            .put("server_port", if (url.port > 0) url.port else when(type) { "socks" -> 1080; "http" -> if (url.scheme == "https") 443 else 80; else -> 443 })
        when (type) {
            "shadowsocks" -> {
                supported("plugin" !in q, "不支持 Shadowsocks 插件")
                val credentials = if (auth.contains(':')) auth else decode64(auth)
                n.put("method", credentials.substringBefore(':')).put("password", credentials.substringAfter(':'))
            }
            "vless", "tuic" -> { n.put("uuid", user); if (type == "tuic") n.put("password", password); q["flow"]?.let { n.put("flow", it) } }
            "trojan", "hysteria2" -> n.put("password", auth)
            else -> n.put("username", user).put("password", password)
        }
        supported(q["encryption"] in setOf(null, "", "none"), "不支持此 VLESS 加密方式")
        transport(n, q["type"].orEmpty(), q["serviceName"] ?: q["path"].orEmpty(), q["host"].orEmpty())
        if (type in setOf("trojan", "hysteria2", "tuic") || q["security"] in setOf("tls", "reality") || url.scheme == "https") {
            val tls = JSONObject().put("enabled", true).put("server_name", q["sni"] ?: q["peer"] ?: host)
            if (q["allowInsecure"] == "1" || q["insecure"] == "1") tls.put("insecure", true)
            q["alpn"]?.let { tls.put("alpn", JSONArray(it.split(','))) }
            q["fp"]?.let { tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", it)) }
            if (q["security"] == "reality") {
                tls.put("reality", JSONObject().put("enabled", true).put("public_key", q["pbk"]).put("short_id", q["sid"].orEmpty()))
                if (!tls.has("utls")) tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", "chrome"))
            }
            n.put("tls", tls)
        }
        if (type == "hysteria2" && q["obfs"] != null) n.put("obfs", JSONObject().put("type", q["obfs"]).put("password", q["obfs-password"]))
        if (type == "tuic") q["congestion_control"]?.let { n.put("congestion_control", it) }
        return n
    }

    private fun clash(p: JSONObject): JSONObject {
        val type = when (val value = p.getString("type")) { "ss" -> "shadowsocks"; "hy2" -> "hysteria2"; "socks5" -> "socks"; else -> value }
        val n = JSONObject().put("type", type).put("tag", p.optString("name")).put("server", p.getString("server")).put("server_port", p.getInt("port"))
        listOf("uuid", "password", "username", "flow").forEach { if (p.has(it)) n.put(it, p.get(it)) }
        supported(!p.has("plugin"), "不支持 Shadowsocks 插件")
        supported(!p.has("dialer-proxy"), "不支持跨节点链式引用，请在本机配置分流")
        if (type == "shadowsocks") n.put("method", p.getString("cipher"))
        if (type == "vmess") n.put("security", p.optString("cipher", "auto")).put("alter_id", p.optInt("alterId"))
        val ws = p.optJSONObject("ws-opts") ?: JSONObject()
        val grpc = p.optJSONObject("grpc-opts") ?: JSONObject()
        transport(n, p.optString("network"), if (p.optString("network") == "grpc") grpc.optString("grpc-service-name") else ws.optString("path"), ws.optJSONObject("headers")?.optString("Host").orEmpty())
        if (p.optBoolean("tls") || type in setOf("trojan", "hysteria2", "tuic") || p.has("reality-opts")) {
            val tls = JSONObject().put("enabled", true).put("server_name", p.optString("servername").ifBlank { p.optString("sni").ifBlank { p.getString("server") } })
            if (p.optBoolean("skip-cert-verify")) tls.put("insecure", true)
            p.optJSONArray("alpn")?.let { tls.put("alpn", it) }
            if (p.has("client-fingerprint")) tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", p.getString("client-fingerprint")))
            p.optJSONObject("reality-opts")?.let {
                tls.put("reality", JSONObject().put("enabled", true).put("public_key", it.getString("public-key")).put("short_id", it.optString("short-id")))
                if (!tls.has("utls")) tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", "chrome"))
            }
            n.put("tls", tls)
        }
        if (type == "hysteria2" && p.has("obfs")) n.put("obfs", JSONObject().put("type", p.getString("obfs")).put("password", p.optString("obfs-password")))
        if (type == "tuic" && p.has("congestion-controller")) n.put("congestion_control", p.getString("congestion-controller"))
        return n
    }

    private fun validate(n: JSONObject) {
        val type = n.optString("type")
        supported(type in protocols, "不支持此代理协议")
        supported(n.optString("server").isNotBlank() && !n.getString("server").any { it.isWhitespace() || it == '/' }, "缺少或无效的服务器地址")
        supported(n.optInt("server_port") in 1..65535, "端口须为 1–65535")
        supported(!n.optString("tag").any { it.code < 32 }, "节点名称含控制字符")
        listOf("plugin", "plugin_opts", "detour", "bind_interface", "routing_mark", "certificate_path", "key_path", "domain_resolver").forEach {
            supported(!n.has(it), "不支持文件、接口绑定或跨节点引用")
        }
        fun inspect(value: Any?, depth: Int = 0) {
            supported(depth < 20, "节点参数嵌套过深")
            when (value) {
                is JSONObject -> value.keys().forEach { key ->
                    supported(!key.endsWith("_path") && key !in setOf("ech", "private_key_path"), "不支持引用本机文件或 ECH 配置")
                    inspect(value.get(key), depth + 1)
                }
                is JSONArray -> (0 until value.length()).forEach { inspect(value.get(it), depth + 1) }
            }
        }
        inspect(n)
        when (type) {
            "vmess", "vless", "tuic" -> supported(runCatching { java.util.UUID.fromString(n.getString("uuid")) }.isSuccess, "缺少或无效的 UUID")
            "shadowsocks" -> supported(n.optString("method").isNotBlank() && n.optString("password").isNotBlank(), "缺少 Shadowsocks 加密方式或密码")
            "trojan", "hysteria2" -> supported(n.optString("password").isNotBlank(), "缺少代理密码")
        }
    }

    fun subscriptionUrl(source: String, allowInsecure: Boolean): String {
        val url = source.trim().toHttpUrlOrNull() ?: error("请输入有效的订阅网址")
        require(url.username.isEmpty() && url.password.isEmpty()) { "请使用订阅令牌网址，不支持 URL 用户名和密码" }
        require(url.isHttps || allowInsecure) { "订阅默认要求 HTTPS；仅对可信局域网启用 HTTP" }
        require(url.fragment == null) { "订阅网址不能包含片段" }
        return url.toString()
    }

    fun baseConfig(subscriptions: List<LocalSubscription>): ManagedConfig {
        val nodes = JSONArray()
        subscriptions.forEach { sub -> sub.nodes.forEach { node ->
            nodes.put(JSONObject(node).put("tag", "sub-${sub.id.take(12)}-${JSONObject(node).getString("tag")}"))
        } }
        require(nodes.length() > 0) { "请先导入至少一个可用代理节点" }
        val content = JSONObject().put("log", JSONObject().put("level", "info").put("timestamp", true))
            .put("inbounds", JSONArray().put(JSONObject().put("type", "tun").put("tag", "tun-in")
                .put("address", JSONArray(listOf("172.19.0.1/30", "fdfe:dcba:9876::1/126")))
                .put("auto_route", true).put("strict_route", true).put("stack", "gvisor").put("mtu", 1500)))
            .put("outbounds", nodes.put(JSONObject().put("type", "direct").put("tag", "direct")))
            .put("route", JSONObject().put("auto_detect_interface", true)
                .put("default_domain_resolver", "bootstrap-dns").put("final", nodes.getJSONObject(0).getString("tag")))
            .put("dns", JSONObject().put("servers", JSONArray().put(JSONObject().put("type", "udp").put("tag", "bootstrap-dns").put("server", "223.5.5.5"))))
            .toString()
        val digest = MessageDigest.getInstance("SHA-256").digest(content.toByteArray()).joinToString("") { "%02x".format(it) }
        return ManagedConfig(content, "local-$digest", "local-subscriptions", "standalone", "本机订阅", System.currentTimeMillis())
    }
}
