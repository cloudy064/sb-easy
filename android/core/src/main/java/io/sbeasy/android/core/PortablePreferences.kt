package io.sbeasy.android.core

import org.json.JSONArray
import org.json.JSONObject

data class PortablePreferences(
    val subscriptions: List<LocalSubscription>,
    val standaloneRouting: LocalRoutingPolicy?,
    val managedRouting: LocalRoutingPolicy?,
)

class PreferencesPreview internal constructor(
    val preferences: PortablePreferences,
    internal val baseline: String,
    val description: String,
)

/** An allowlist schema. Device credentials, capture/CA state and package rules have no representation. */
object PreferencesPayload {
    fun encode(value: PortablePreferences): String = JSONObject().put("format", "sb-easy.preferences.payload")
        .put("version", 1).put("platform", "android").put("preferences", JSONObject()
            .put("subscriptions", JSONArray().also { rows -> value.subscriptions.forEach { sub ->
                val nodes = JSONArray().also { entries -> sub.nodes.forEach { entries.put(JSONObject(it)) } }
                // A pasted whole configuration can contain discarded WG endpoints or
                // scripts. Export only the accepted proxy nodes, never the raw document.
                val source = if (sub.remote) sub.source else JSONObject().put("outbounds", nodes).toString()
                rows.put(JSONObject().put("id", sub.id).put("name", sub.name).put("source", source).put("remote", sub.remote)
                    .put("allow_insecure", sub.allowInsecure).put("interval_minutes", sub.intervalMinutes)
                    .put("nodes", nodes))
            } }).put("standalone_routing", value.standaloneRouting?.let(::routingJson) ?: JSONObject.NULL)
            .put("managed_routing", value.managedRouting?.let(::routingJson) ?: JSONObject.NULL)).toString()

    private fun routingJson(policy: LocalRoutingPolicy): JSONObject {
        // App-only groups do not travel. Mixed groups retain domains and choices only.
        val json = JSONObject(LocalRouting.encode(policy.copy(groups = policy.groups.filter { it.domains.isNotEmpty() })))
        val groups = json.getJSONArray("groups")
        for (index in 0 until groups.length()) { groups.getJSONObject(index).remove("packages"); groups.getJSONObject(index).remove("include_official_app") }
        return json
    }

    fun decode(payload: String): PortablePreferences {
        require(payload.toByteArray(Charsets.UTF_8).size <= PreferencesEnvelope.MAX_BYTES) { "偏好数据超过 1 MiB" }
        val root = JSONObject(payload)
        keys(root, setOf("format", "version", "platform", "preferences"))
        require(root.opt("format") == "sb-easy.preferences.payload" && root.opt("version") == 1) { "不支持的偏好内容版本" }
        require(root.opt("platform") == "android") { "此文件来自其他平台；加密格式通用，但路由内容目前只支持 Android 之间导入" }
        val body = root.getJSONObject("preferences")
        keys(body, setOf("subscriptions", "standalone_routing", "managed_routing"))
        for (name in listOf("standalone_routing", "managed_routing")) require(body.isNull(name) || body.opt(name) is JSONObject) { "无效的路由偏好内容" }
        val rows = body.getJSONArray("subscriptions")
        require(rows.length() <= 16) { "最多导入 16 个订阅" }
        val subscriptions = (0 until rows.length()).map { index ->
            val row = rows.getJSONObject(index)
            keys(row, setOf("id", "name", "source", "remote", "allow_insecure", "interval_minutes", "nodes"))
            val id = row.getString("id"); val name = row.getString("name")
            require(id.matches(Regex("[a-zA-Z0-9-]{1,64}"))) { "无效订阅 ID" }
            require(name.isNotBlank() && name.length <= 80) { "订阅名称须为 1–80 个字符" }
            require(row.opt("remote") is Boolean && row.opt("allow_insecure") is Boolean) { "无效订阅类型" }
            val remote = row.getBoolean("remote"); val insecure = row.getBoolean("allow_insecure")
            val interval = row.getInt("interval_minutes")
            require(interval == 0 || remote && interval in 15..10080) { "无效订阅更新间隔" }
            val source = row.getString("source")
            require(source.isNotBlank()) { "订阅内容为空" }
            if (remote) SubscriptionParser.subscriptionUrl(source, insecure)
            val nodes = row.getJSONArray("nodes")
            require(nodes.length() in 1..SubscriptionParser.MAX_NODES) { "订阅节点数量无效" }
            val parsed = SubscriptionParser.parse(nodes.toString())
            require(parsed.issues.isEmpty() && parsed.nodes.size == nodes.length()) { "订阅包含不支持或不安全的节点，请先修复源设备订阅" }
            // Normalization must not silently rename tags referenced by routing rules.
            require((0 until nodes.length()).map { nodes.getJSONObject(it).getString("tag") } == parsed.nodes.map { it.getString("tag") }) { "订阅节点名称重复或不规范" }
            LocalSubscription(id, name, source, remote, insecure, interval, parsed.nodes.map(JSONObject::toString), format = parsed.format)
        }
        require(subscriptions.map { it.id }.distinct().size == subscriptions.size &&
            subscriptions.map { it.id.take(12) }.distinct().size == subscriptions.size) { "订阅 ID 冲突" }
        return PortablePreferences(subscriptions, readRouting(body.optJSONObject("standalone_routing")), readRouting(body.optJSONObject("managed_routing")))
    }

    private fun readRouting(json: JSONObject?): LocalRoutingPolicy? {
        if (json == null) return null
        keys(json, setOf("schema_version", "default_outbound", "default_automatic_candidates", "health", "preset_revision", "groups"))
        require(json.opt("schema_version") == 2) { "不支持的路由偏好版本" }
        keys(json.getJSONObject("health"), setOf("enabled", "probe_url", "interval_seconds", "timeout_millis", "tolerance_millis", "selection"))
        val rows = json.getJSONArray("groups")
        for (index in 0 until rows.length()) {
            val row = rows.getJSONObject(index)
            keys(row, setOf("id", "name", "domains", "outbound", "automatic_candidates"))
            row.put("include_official_app", false)
        }
        return LocalRouting.decode(json.toString())
    }

    /** Preserve the target device's explicit app choices, including groups with no portable domains. */
    fun retainDeviceRules(imported: LocalRoutingPolicy?, current: LocalRoutingPolicy?): LocalRoutingPolicy? {
        if (imported == null) return current
        val target = current?.groups.orEmpty().associateBy { it.id }
        val groups = imported.groups.map { group ->
            val old = target[group.id]
            require(old == null || LocalRouting.effectivePackages(old).isEmpty() ||
                old.outbound == group.outbound && old.automaticCandidates == group.automaticCandidates) {
                "分组「${group.name}」与本机应用出口冲突，请先在代理页调整该应用分组"
            }
            group.copy(includeOfficialApp = old?.includeOfficialApp ?: false, packages = old?.packages.orEmpty())
        } + current?.groups.orEmpty().filter { LocalRouting.effectivePackages(it).isNotEmpty() && it.id !in imported.groups.map { row -> row.id } }
            .map { it.copy(domains = emptyList()) }
        return imported.copy(groups = groups).also(LocalRouting::validate)
    }

    private fun keys(json: JSONObject, allowed: Set<String>) {
        require(json.keys().asSequence().toSet() == allowed) { "偏好文件含不支持或设备专属的字段" }
    }
}
