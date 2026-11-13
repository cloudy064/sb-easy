package io.sbeasy.android.core

import android.content.Context
import org.json.JSONObject

/** Applied cache for native settings; the sync outbox remains the source of pending edits. */
interface PlatformConfigurationStorage {
    fun selectors(): JSONObject
    fun legacySelectors(): JSONObject = selectors()
    fun saveSelectors(value: JSONObject)
    fun captureTemplate(): JSONObject
    fun saveCaptureTemplate(value: JSONObject)
}

class PlatformConfigurationStore(context: Context) : PlatformConfigurationStorage {
    private val selections = context.getSharedPreferences("sb_easy_managed_selectors", Context.MODE_PRIVATE)
    private val legacy = context.getSharedPreferences("sb_easy_proxy_selections", Context.MODE_PRIVATE)
    override fun selectors(): JSONObject = readSelections(selections)
    override fun legacySelectors(): JSONObject = readSelections(if (selections.getBoolean("initialized", false)) selections else legacy)
    private fun readSelections(source: android.content.SharedPreferences): JSONObject = JSONObject().also { out ->
        source.all.forEach { (tag, selected) ->
            if (selected is String && !tag.startsWith(LocalRouting.TAG_PREFIX)) out.put(tag, selected)
        }
    }
    override fun saveSelectors(value: JSONObject) {
        val edit = selections.edit().clear().putBoolean("initialized", true)
        value.keys().forEach { edit.putString(it, value.getString(it)) }
        check(edit.commit()) { "节点选择缓存保存失败" }
    }
    override fun captureTemplate(): JSONObject = captureTemplate(PacketCapture.config())
    override fun saveCaptureTemplate(value: JSONObject) {
        val session = PacketCapture.config()
        val next = ConfigMergePatch.apply(captureTemplate(CaptureConfig()), value)
            .put("enabled", session.enabled).put("auto_upload", session.autoUpload)
        val config = CaptureConfig.parse(next.toString())
        if (config.enabled) PacketCapture.validateFilter(config.bpf)
        PacketCapture.save(config)
    }
}

internal fun captureTemplate(config: CaptureConfig): JSONObject = config.json().also {
    // These two choices require an explicitly opened capture session on this device.
    it.remove("enabled"); it.remove("auto_upload")
}
