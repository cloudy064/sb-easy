package io.sbeasy.android.core

import org.json.JSONArray
import org.json.JSONObject

object ConfigInspector {
    private val sensitiveKeys = setOf(
        "password", "uuid", "private_key", "pre_shared_key", "secret", "token",
        "auth", "authorization", "client_secret",
    )

    fun inspect(content: String): ConfigSummary {
        val root = JSONObject(content)
        val inbounds = root.optJSONArray("inbounds") ?: JSONArray()
        val outboundArray = root.optJSONArray("outbounds") ?: JSONArray()
        val route = root.optJSONObject("route") ?: JSONObject()
        val rules = route.optJSONArray("rules") ?: JSONArray()
        val dnsServers = root.optJSONObject("dns")?.optJSONArray("servers")?.length() ?: 0
        return ConfigSummary(
            inboundTypes = buildList {
                for (index in 0 until inbounds.length()) {
                    add(inbounds.optJSONObject(index)?.optString("type", "unknown") ?: "unknown")
                }
            },
            dnsServers = dnsServers,
            routeRules = buildList {
                for (index in 0 until rules.length()) add(describeRule(index + 1, rules.optJSONObject(index)))
            },
            routeFinal = route.optString("final", "direct"),
            outboundTags = buildList {
                for (index in 0 until outboundArray.length()) {
                    outboundArray.optJSONObject(index)?.optString("tag")?.takeIf { it.isNotBlank() }?.let(::add)
                }
            },
            sanitizedJson = (sanitize(root) as JSONObject).toString(2),
        )
    }

    private fun describeRule(number: Int, rule: JSONObject?): String {
        if (rule == null) return "$number. 无效规则"
        val target = rule.optString("outbound", rule.optString("action", "继续匹配"))
        val conditions = buildList {
            addValues(rule, "domain", "域名", this)
            addValues(rule, "domain_suffix", "域名后缀", this)
            addValues(rule, "ip_cidr", "IP 网段", this)
            addValues(rule, "protocol", "协议", this)
            addValues(rule, "port", "端口", this)
            if (rule.optBoolean("ip_is_private", false)) add("私有地址")
            if (rule.has("rule_set")) add("规则集 ${compact(rule.opt("rule_set"))}")
        }
        return "$number. ${conditions.ifEmpty { listOf("所有流量") }.joinToString("；")} → $target"
    }

    private fun addValues(rule: JSONObject, key: String, label: String, output: MutableList<String>) {
        if (rule.has(key)) output.add("$label ${compact(rule.opt(key))}")
    }

    private fun compact(value: Any?): String = when (value) {
        is JSONArray -> buildList {
            for (index in 0 until minOf(value.length(), 3)) add(value.opt(index).toString())
        }.joinToString(", ") + if (value.length() > 3) "…" else ""
        else -> value?.toString().orEmpty()
    }

    private fun sanitize(value: Any?): Any = when (value) {
        is JSONObject -> JSONObject().also { output ->
            val keys = value.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                output.put(key, if (key.lowercase() in sensitiveKeys) "••••••••" else sanitize(value.opt(key)))
            }
        }
        is JSONArray -> JSONArray().also { output ->
            for (index in 0 until value.length()) output.put(sanitize(value.opt(index)))
        }
        JSONObject.NULL -> JSONObject.NULL
        else -> value ?: JSONObject.NULL
    }
}
