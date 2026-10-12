package io.sbeasy.android.core

import org.json.JSONArray
import org.json.JSONObject

object HttpDebugRouting {
    fun normalize(text: String): List<String> = text.split(Regex("[\\s,，]+"))
        .filter(String::isNotBlank).map { it.lowercase() }.distinct().also { domains ->
            require(domains.size in 1..64) { "请填写 1–64 个抓包域名" }
            require(domains.all { it.length <= 253 && it.matches(Regex("[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) }) { "请填写域名，不要包含网址路径或通配符" }
        }

    fun apply(content: String, domains: List<String>, password: String): String {
        normalize(domains.joinToString(" "))
        require(password.matches(Regex("[0-9a-f]{64}")))
        val root = JSONObject(content)
        val inbounds = root.getJSONArray("inbounds")
        val outbounds = root.getJSONArray("outbounds")
        val route = root.optJSONObject("route") ?: JSONObject().also { root.put("route", it) }
        val previous = route.optJSONArray("rules") ?: JSONArray()
        val tags = JSONArray()
        for (i in 0 until inbounds.length()) {
            val inbound = inbounds.getJSONObject(i)
            require(!inbound.optString("tag").startsWith("sb-httpdebug-")) { "抓包标记与配置冲突" }
            if (inbound.optString("type") == "tun") {
                if (inbound.optString("tag").isBlank()) inbound.put("tag", "sb-httpdebug-tun-$i")
                tags.put(inbound.getString("tag"))
            }
        }
        require(tags.length() > 0) { "请先启用 VPN 连接" }
        for (i in 0 until outbounds.length()) require(!outbounds.getJSONObject(i).optString("tag").startsWith("sb-httpdebug-"))
        inbounds.put(JSONObject().put("type", "http").put("tag", "sb-httpdebug-upstream")
            .put("listen", "127.0.0.1").put("listen_port", 17992))
        outbounds.put(JSONObject().put("type", "http").put("tag", "sb-httpdebug-engine")
            .put("server", "127.0.0.1").put("server_port", 17990).put("username", "sbeasy").put("password", password))
        val match = JSONObject().put("inbound", tags).put("domain_suffix", JSONArray(domains))
        val sniff = JSONObject().put("inbound", tags).put("action", "sniff")
        val quic = JSONObject(match.toString()).put("network", "udp").put("port", 443).put("action", "reject")
        val capture = JSONObject(match.toString()).put("network", "tcp").put("port", JSONArray(listOf(80, 443)))
            .put("action", "route").put("outbound", "sb-httpdebug-engine")
        val rules = JSONArray().put(sniff).put(quic).put(capture)
        for (i in 0 until previous.length()) rules.put(previous.get(i))
        route.put("rules", rules)
        return root.toString()
    }
}
