package io.sbeasy.android.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject

data class LocalSubscription(
    val id: String,
    val name: String,
    val source: String,
    val remote: Boolean,
    val allowInsecure: Boolean = false,
    val intervalMinutes: Int = 360,
    val nodes: List<String> = emptyList(),
    val quota: SubscriptionQuota = SubscriptionQuota(),
    val issues: List<SubscriptionIssue> = emptyList(),
    val format: String = "",
    val lastSuccess: Long = 0,
    val lastAttempt: Long = 0,
    val error: String? = null,
) {
    fun due(now: Long): Boolean = remote && intervalMinutes > 0 &&
        (lastAttempt == 0L || now < lastAttempt || now - lastAttempt >= intervalMinutes * 60_000L)

    fun json(): JSONObject = JSONObject().put("id", id).put("name", name).put("source", source).put("remote", remote)
        .put("allow_insecure", allowInsecure).put("interval_minutes", intervalMinutes).put("nodes", JSONArray(nodes))
        .put("quota", quota.json()).put("issues", JSONArray().also { array -> issues.forEach { array.put(JSONObject().put("index", it.index).put("reason", it.reason)) } })
        .put("format", format).put("last_success", lastSuccess).put("last_attempt", lastAttempt).put("error", error)

    companion object {
        fun fromJson(json: JSONObject): LocalSubscription {
            val nodes = json.getJSONArray("nodes")
            val issues = json.optJSONArray("issues") ?: JSONArray()
            return LocalSubscription(
                id = json.getString("id"), name = json.getString("name"), source = json.getString("source"), remote = json.getBoolean("remote"),
                allowInsecure = json.optBoolean("allow_insecure"), intervalMinutes = json.optInt("interval_minutes", 360),
                nodes = (0 until nodes.length()).map(nodes::getString), quota = SubscriptionQuota.fromJson(json.optJSONObject("quota") ?: JSONObject()),
                issues = (0 until issues.length()).map { val item = issues.getJSONObject(it); SubscriptionIssue(item.getInt("index"), item.getString("reason")) },
                format = json.optString("format"), lastSuccess = json.optLong("last_success"), lastAttempt = json.optLong("last_attempt"),
                error = json.optString("error").takeIf { it.isNotBlank() },
            )
        }
    }
}

/** Subscription URLs, manual sources and node passwords share an authenticated, atomic encrypted envelope. */
class LocalSubscriptionStore(context: Context) : SubscriptionStorage {
    private val file = AtomicFile(File(context.filesDir, "subscriptions.encrypted.json"))
    private val preferences = context.getSharedPreferences("client_mode", Context.MODE_PRIVATE)
    override fun mode(): ClientMode = runCatching { ClientMode.valueOf(preferences.getString("mode", "MANAGED")!!) }.getOrDefault(ClientMode.MANAGED)
    override fun setMode(mode: ClientMode) { check(preferences.edit().putString("mode", mode.name).commit()) { "无法保存客户端模式" } }
    @Synchronized override fun load(): List<LocalSubscription> {
        if (!file.baseFile.exists()) return emptyList()
        // Corrupt/authentication-failed storage must be surfaced rather than overwritten silently.
        val envelope = JSONObject(file.openRead().bufferedReader().use { it.readText() })
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, requireNotNull(envelope.getString("iv").decodeBase64()).toByteArray()))
        val plaintext = cipher.doFinal(requireNotNull(envelope.getString("payload").decodeBase64()).toByteArray())
        val json = JSONArray(String(plaintext, Charsets.UTF_8))
        return (0 until json.length()).map { LocalSubscription.fromJson(json.getJSONObject(it)) }
    }
    @Synchronized override fun save(subscriptions: List<LocalSubscription>) {
        val json = JSONArray().also { array -> subscriptions.forEach { array.put(it.json()) } }.toString()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val envelope = JSONObject().put("iv", cipher.iv.toByteString().base64())
            .put("payload", cipher.doFinal(json.toByteArray()).toByteString().base64()).toString()
        val output = file.startWrite()
        try { output.write(envelope.toByteArray()); file.finishWrite(output) }
        catch (error: Throwable) { file.failWrite(output); throw error }
    }
    private fun key(): SecretKey {
        val alias = "sb_easy_local_subscriptions_v1"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance("AES", "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build())
            generateKey()
        }
    }
}

class SubscriptionFetcher : SubscriptionSource {
    // This client has no interceptor, cookie jar or enrollment credentials. Never reuse ControlPlaneClient.
    private val client = OkHttpClient.Builder().connectTimeout(15, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS)
        .callTimeout(45, TimeUnit.SECONDS).followRedirects(false).followSslRedirects(false).build()
    data class Download(val content: String, val quota: SubscriptionQuota)
    override fun fetch(source: String, allowInsecure: Boolean): Download {
        var url = SubscriptionParser.subscriptionUrl(source, allowInsecure)
        repeat(6) {
            val request = Request.Builder().url(url).header("User-Agent", "sb-easy-android/subscription").get().build()
            client.newCall(request).execute().use { response ->
                if (response.code in setOf(301, 302, 303, 307, 308)) {
                    val target = response.header("Location")?.let { request.url.resolve(it) } ?: error("订阅重定向缺少有效地址")
                    // A TLS URL can never downgrade even when the original local HTTP source was opted in.
                    require(!request.url.isHttps || target.isHttps) { "订阅重定向不允许从 HTTPS 降级到 HTTP" }
                    url = SubscriptionParser.subscriptionUrl(target.toString(), allowInsecure)
                } else {
                    require(response.isSuccessful) { "订阅下载失败：HTTP ${response.code}" }
                    val body = requireNotNull(response.body) { "订阅返回空内容" }
                    require(body.contentLength() <= SubscriptionParser.MAX_BYTES) { "订阅超过 1 MB" }
                    val sourceStream = body.source()
                    val bounded = okio.Buffer()
                    while (bounded.size <= SubscriptionParser.MAX_BYTES) {
                        val count = sourceStream.read(bounded, minOf(8192L, SubscriptionParser.MAX_BYTES + 1L - bounded.size))
                        if (count == -1L) break
                    }
                    val bytes = bounded.readByteArray()
                    require(bytes.size <= SubscriptionParser.MAX_BYTES) { "订阅超过 1 MB" }
                    return Download(String(bytes, Charsets.UTF_8), SubscriptionQuota.parse(response.header("Subscription-Userinfo")))
                }
            }
        }
        error("订阅重定向次数过多")
    }
}
