package io.sbeasy.android.core

import org.json.JSONArray
import org.json.JSONObject

/** Durable cache/outbox. The center owns committed configuration; device clocks never select a winner. */
interface ConfigSyncStorage {
    fun load(): JSONObject?
    fun save(value: JSONObject)
    fun clear()
}

internal object ConfigMergePatch {
    fun apply(base: JSONObject, patch: JSONObject): JSONObject = JSONObject(base.toString()).also { out ->
        patch.keys().forEach { key ->
            val value = patch.get(key)
            when (value) {
                JSONObject.NULL -> out.remove(key)
                is JSONObject -> out.put(key, apply(out.optJSONObject(key) ?: JSONObject(), value))
                else -> out.put(key, copy(value))
            }
        }
    }
    fun diff(base: JSONObject, value: JSONObject): JSONObject = JSONObject().also { out ->
        base.keys().forEach { if (!value.has(it)) out.put(it, JSONObject.NULL) }
        value.keys().forEach { key ->
            val next = value.get(key)
            if (!equal(base.opt(key), next)) {
                out.put(key, if (next is JSONObject) diff(base.optJSONObject(key) ?: JSONObject(), next) else copy(next))
            }
        }
    }
    /** Replace understood fields while retaining fields written by newer clients. */
    fun replaceKnown(old: JSONObject, shape: JSONObject, next: JSONObject): JSONObject = JSONObject(old.toString()).also { out ->
        shape.keys().forEach { key ->
            val value = next.opt(key)
            when {
                shape.opt(key) is JSONObject && (value is JSONObject || value == null) -> {
                    val retained = replaceKnown(old.optJSONObject(key) ?: JSONObject(), shape.getJSONObject(key), value as? JSONObject ?: JSONObject())
                    if (retained.length() == 0 && value == null) out.remove(key) else out.put(key, retained)
                }
                value == null -> out.remove(key)
                value is JSONArray && shape.optJSONArray(key)?.optJSONObject(0) != null -> {
                    val schema = shape.getJSONArray(key).getJSONObject(0)
                    val previous = old.optJSONArray(key)
                    val retained = JSONArray()
                    for (index in 0 until value.length()) {
                        val item = value.optJSONObject(index)
                        val prior = (0 until (previous?.length() ?: 0)).mapNotNull { previous?.optJSONObject(it) }
                            .firstOrNull { item != null && it.optString("id") == item.optString("id") }
                        retained.put(if (item == null) value.get(index) else replaceKnown(prior ?: JSONObject(), schema, item))
                    }
                    out.put(key, retained)
                }
                else -> out.put(key, copy(value))
            }
        }
    }
    fun equal(a: Any?, b: Any?): Boolean = when {
        a is JSONObject && b is JSONObject -> a.keySet() == b.keySet() && a.keySet().all { equal(a.opt(it), b.opt(it)) }
        a is JSONArray && b is JSONArray -> a.length() == b.length() && (0 until a.length()).all { equal(a.get(it), b.get(it)) }
        else -> a == b
    }
    private fun JSONObject.keySet(): Set<String> = keys().asSequence().toSet()
    private fun copy(value: Any): Any = when (value) {
        is JSONObject -> JSONObject(value.toString())
        is JSONArray -> JSONArray(value.toString())
        else -> value
    }
}

internal class ManagedConfigSync(private val storage: ConfigSyncStorage, private val client: AgentControlPlane) {
    private fun binding(enrollment: Enrollment) = enrollment.server + "\n" + enrollment.hostId
    private fun cached(enrollment: Enrollment): JSONObject? = storage.load()?.also {
        check(it.optString("device") == binding(enrollment)) { "配置同步缓存属于其他设备，请先解除旧设备注册" }
    }

    fun synchronize(enrollment: Enrollment, legacyPolicy: LocalRoutingPolicy?, legacySettings: JSONObject = JSONObject()): JSONObject? {
        var local = cached(enrollment)
        var remote = client.fetchConfigState(enrollment) ?: return null
        validate(remote)
        // Convert existing policy only on the first successful migration, without replacing a remote customization.
        if (local == null) {
            local = JSONObject().put("device", binding(enrollment)).put("snapshot", remote)
            if (legacyPolicy != null) local.put("legacy_backup", JSONObject(LocalRouting.encode(legacyPolicy)))
            if (legacySettings.length() != 0) local.put("legacy_platform_backup", JSONObject(legacySettings.toString()))
            storage.save(local)
            if (!remote.optBoolean("agent_settings_initialized", false) && remote.getJSONObject("agent_settings").length() == 0) {
                if (legacyPolicy != null) queue(enrollment, legacyPolicy, remote.getJSONObject("config").toString())
                if (legacySettings.length() != 0) queueSettings(enrollment, legacySettings)
                local = cached(enrollment)!!
            }
        }
        val pending = local.optJSONObject("pending")
        if (pending != null) {
            val alreadyAccepted = ConfigMergePatch.equal(pending.getJSONObject("patch"), remote.getJSONObject("patch")) &&
                ConfigMergePatch.equal(pending.getJSONObject("agent_settings"), remote.getJSONObject("agent_settings"))
            if (!alreadyAccepted) {
                try {
                    remote = client.putConfigState(enrollment, pending)
                    validate(remote)
                } catch (error: ControlPlaneException) {
                    if (error.statusCode == 409) {
                        local.put("remote", remote).put("conflict", true)
                        storage.save(local)
                        throw ControlPlaneException("服务器和本机配置均已修改；本机待同步修改已保留，请选择保留本机或采用服务器配置", 409)
                    }
                    throw error
                }
            }
        }
        val committed = JSONObject().put("device", binding(enrollment)).put("snapshot", remote)
        local.optJSONObject("legacy_backup")?.let { committed.put("legacy_backup", it) }
        local.optJSONObject("legacy_platform_backup")?.let { committed.put("legacy_platform_backup", it) }
        storage.save(committed)
        return remote
    }

    fun settings(enrollment: Enrollment): JSONObject? = cached(enrollment)?.let {
        val snapshot = it.optJSONObject("pending") ?: it.getJSONObject("snapshot")
        JSONObject(snapshot.getJSONObject("agent_settings").toString())
    }

    fun queue(enrollment: Enrollment, policy: LocalRoutingPolicy, content: String) {
        val settings = settings(enrollment) ?: return
        val shape = JSONObject(LocalRouting.encode(LocalRouting.defaults(content)))
        val delta = ConfigMergePatch.diff(shape, JSONObject(LocalRouting.encode(policy)))
        val retained = ConfigMergePatch.replaceKnown(settings.optJSONObject("android_routing") ?: JSONObject(), shape, delta)
        queueSettings(enrollment, JSONObject().put("android_routing", if (retained.length() == 0) JSONObject.NULL else retained))
    }

    fun queueSettings(enrollment: Enrollment, changes: JSONObject) {
        val local = cached(enrollment) ?: return // Legacy center; migration preserves existing local settings.
        val snapshot = local.getJSONObject("snapshot")
        val previous = local.optJSONObject("pending")
        val settings = JSONObject((previous ?: snapshot).getJSONObject("agent_settings").toString())
        changes.keys().forEach { key ->
            if (changes.isNull(key)) settings.remove(key) else settings.put(key, changes.get(key))
        }
        val pending = JSONObject()
            .put("base_version", (previous ?: snapshot).getLong("base_version"))
            .put("patch_version", (previous ?: snapshot).getLong("patch_version"))
            .put("patch", JSONObject((previous ?: snapshot).getJSONObject("patch").toString()))
            .put("agent_settings", settings)
        local.put("pending", pending)
        storage.save(local)
    }

    fun policy(snapshot: JSONObject): LocalRoutingPolicy {
        val defaults = JSONObject(LocalRouting.encode(LocalRouting.defaults(snapshot.getJSONObject("config").toString())))
        return LocalRouting.decode(ConfigMergePatch.apply(defaults, snapshot.getJSONObject("agent_settings").optJSONObject("android_routing") ?: JSONObject()).toString())
    }

    fun resolve(enrollment: Enrollment, keepLocal: Boolean) {
        val local = requireNotNull(cached(enrollment)) { "没有待处理的配置冲突" }
        val remote = requireNotNull(local.optJSONObject("remote")) { "请先同步并检查冲突" }
        if (keepLocal) {
            val pending = local.getJSONObject("pending")
            pending.put("base_version", remote.getLong("base_version")).put("patch_version", remote.getLong("patch_version"))
            local.put("snapshot", remote).remove("conflict")
            local.remove("remote")
            storage.save(local)
        } else storage.save(JSONObject().put("device", binding(enrollment)).put("snapshot", remote))
    }

    fun clear() = storage.clear()

    private fun validate(value: JSONObject) {
        require(value.getLong("base_version") > 0 && value.getLong("patch_version") >= 0) { "无效配置版本" }
        value.getJSONObject("base"); value.getJSONObject("config"); value.getJSONObject("patch"); value.getJSONObject("agent_settings")
    }
}

internal fun applyManagedSelections(content: String, selections: JSONObject): String {
    require(selections.length() <= 256) { "最多保存 256 个代理组选择" }
    val config = JSONObject(content)
    val outbounds = config.optJSONArray("outbounds") ?: JSONArray()
    selections.keys().forEach { tag ->
        require(tag.isNotBlank() && tag.length <= 512 && selections.opt(tag) is String) { "无效代理组选择" }
        val selected = selections.getString(tag)
        require(selected.isNotBlank() && selected.length <= 512 && !tag.startsWith(LocalRouting.TAG_PREFIX)) { "无效代理组选择" }
        val group = (0 until outbounds.length()).mapNotNull { outbounds.optJSONObject(it) }
            .firstOrNull { it.optString("tag") == tag && it.optString("type") == "selector" }
        if (group != null) {
            val nodes = group.optJSONArray("outbounds") ?: JSONArray()
            require((0 until nodes.length()).any { nodes.optString(it) == selected }) { "代理组 $tag 的指定节点已失效，请重新选择" }
            group.put("default", selected)
        }
    }
    return config.toString()
}

fun managedSelectorDefaults(content: String): Map<String, String> {
    val outbounds = JSONObject(content).optJSONArray("outbounds") ?: JSONArray()
    return (0 until outbounds.length()).mapNotNull { outbounds.optJSONObject(it) }
        .filter { it.optString("type") == "selector" }
        .mapNotNull { group ->
            val selected = group.optString("default").takeIf { it.isNotBlank() } ?: group.optJSONArray("outbounds")?.optString(0).orEmpty()
            selected.takeIf { it.isNotBlank() }?.let { group.getString("tag") to it }
        }.toMap()
}
