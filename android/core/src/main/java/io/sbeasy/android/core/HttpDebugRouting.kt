package io.sbeasy.android.core

import org.json.JSONArray
import org.json.JSONObject

object HttpDebugRouting {
    fun normalize(text: String): List<String> = LocalRouting.normalizeDomains(text).also {
        require(it.size <= 64) { "最多填写 64 个调试域名" }
    }

    /** Only domain-routed TUN traffic is intercepted. Application and private routes keep priority. */
    fun apply(content: String, domains: List<String>, password: String): String {
        require(normalize(domains.joinToString(" ")) == domains)
        require(password.matches(Regex("[0-9a-f]{64}"))) { "插件会话凭据无效" }
        val root = JSONObject(content)
        val inbounds = root.getJSONArray("inbounds")
        val outbounds = root.getJSONArray("outbounds")
        val route = root.optJSONObject("route") ?: JSONObject().also { root.put("route", it) }
        val previous = objects(route.optJSONArray("rules"))
        val endpoints = objects(root.optJSONArray("endpoints")).map { it.optString("tag") }.toSet()
        val tags = JSONArray()
        for (inbound in objects(inbounds)) {
            require(!inbound.optString("tag").startsWith("sb-httpdebug-")) { "调试标记与配置冲突" }
            if (inbound.optString("type") == "tun") {
                if (inbound.optString("tag").isBlank()) inbound.put("tag", "sb-httpdebug-tun-${tags.length()}")
                tags.put(inbound.getString("tag"))
            }
        }
        require(tags.length() > 0) { "请先启用 VPN 连接" }
        require(objects(outbounds).none { it.optString("tag").startsWith("sb-httpdebug-") }) { "调试出口与配置冲突" }
        require(previous.none { it.optJSONArray("package_name")?.toString()?.contains("\"io.sbeasy.httpdebug\"") == true }) {
            "请先移除 HTTP 调试插件自身的应用分流规则"
        }
        // Both legs are authenticated. Another local app must not gain an open proxy.
        inbounds.put(JSONObject().put("type", "http").put("tag", "sb-httpdebug-upstream")
            .put("listen", "127.0.0.1").put("listen_port", 17992)
            .put("users", JSONArray().put(JSONObject().put("username", "sbeasy").put("password", password))))
        outbounds.put(JSONObject().put("type", "http").put("tag", "sb-httpdebug-engine")
            .put("server", "127.0.0.1").put("server_port", 17990).put("username", "sbeasy").put("password", password))
        val match = JSONObject().put("inbound", tags).put("domain_suffix", JSONArray(domains))
        val quic = JSONObject(match.toString()).put("network", "udp").put("port", 443).put("action", "reject")
        val capture = JSONObject(match.toString()).put("network", "tcp").put("port", JSONArray(listOf(80, 443)))
            .put("action", "route").put("outbound", "sb-httpdebug-engine")
        fun protected(rule: JSONObject): Boolean = rule.optString("action") in setOf("sniff", "hijack-dns", "resolve") ||
            rule.has("package_name") || rule.has("process_name") || rule.has("process_path") ||
            rule.has("ip_is_private") || rule.has("ip_cidr") || rule.optString("outbound") in endpoints ||
            (rule.optString("outbound") == "direct" && rule.has("domain"))
        val rules = JSONArray()
        if (previous.none { it.optString("action") == "sniff" }) rules.put(JSONObject().put("inbound", tags).put("action", "sniff"))
        previous.filter(::protected).forEach(rules::put)
        rules.put(quic).put(capture)
        previous.filterNot(::protected).forEach(rules::put)
        route.put("rules", rules)
        return root.toString()
    }

    private fun objects(array: JSONArray?): List<JSONObject> = (0 until (array?.length() ?: 0)).map { array!!.getJSONObject(it) }
}
