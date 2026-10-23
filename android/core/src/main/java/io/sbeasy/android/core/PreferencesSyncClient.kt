package io.sbeasy.android.core

import java.util.concurrent.TimeUnit
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

data class RemotePreferences(val revision: Long, val updatedAt: Long = 0, val envelope: String? = null, val deleted: Boolean = false)

/** Separate account login, with ephemeral flow cookies/session; never uses an agent token. */
class PreferencesSyncClient(server: String, transport: OkHttpClient? = null) {
    private val base = requireNotNull(server.trim().toHttpUrlOrNull()) { "请输入有效的 HTTPS 中心地址" }.also {
        require(it.isHttps && it.username.isEmpty() && it.password.isEmpty() && it.query == null && it.fragment == null) { "中心漫游要求 HTTPS，且地址不能含账户信息、查询或片段" }
    }
    private val jar = object : CookieJar {
        var cookies: List<Cookie> = emptyList()
        override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
            this.cookies = (this.cookies + cookies.filter { it.name == "sb_auth_flow" }).associateBy { it.name }.values
                .filter { it.expiresAt > System.currentTimeMillis() }
        }
        override fun loadForRequest(url: HttpUrl): List<Cookie> = cookies.filter { it.matches(url) && it.expiresAt > System.currentTimeMillis() }
    }
    private val client = (transport?.newBuilder() ?: OkHttpClient.Builder()).cookieJar(jar)
        .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
        .connectTimeout(15, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS).callTimeout(45, TimeUnit.SECONDS).build()
    private var token: String? = null
    private var challenge: String? = null
    val authenticated get() = token != null

    /** Returns true when a second factor is required. */
    fun login(username: String, password: String): Boolean {
        require(username.isNotBlank() && username.length <= 256 && password.isNotEmpty()) { "请填写中心账户和密码" }
        token = null; challenge = null; jar.cookies = emptyList()
        val (_, body) = request("POST", "api/auth/login", JSONObject().put("username", username).put("password", password).toString(), authenticated = false)
        if (body.optBoolean("mfa_required")) {
            challenge = body.getString("challenge").also { require(it.length in 1..4096) { "无效的 MFA 挑战" } }
            return true
        }
        token = body.getString("token").also { require(it.length in 1..8192) { "无效的登录会话" } }
        return false
    }

    fun completeMfa(code: String) {
        require(code.isNotBlank() && code.length <= 128) { "请填写动态码或恢复码" }
        val (_, body) = request("POST", "api/auth/login/mfa", JSONObject().put("challenge", requireNotNull(challenge) { "请重新登录" }).put("code", code).toString(), authenticated = false)
        token = body.getString("token").also { require(it.length in 1..8192) { "无效的登录会话" } }
        challenge = null; jar.cookies = emptyList()
    }

    fun get(slot: String): RemotePreferences {
        val (code, body) = request("GET", slotPath(slot), allowMissing = true)
        return if (code == 404) RemotePreferences(0) else remote(body)
    }

    fun put(slot: String, revision: Long, envelope: String): RemotePreferences {
        require(revision >= 0) { "无效的云端版本" }
        PreferencesEnvelope.inspect(envelope)
        return remote(request("PUT", slotPath(slot), envelope, revision).second)
    }

    fun delete(slot: String, revision: Long): RemotePreferences {
        require(revision >= 0) { "无效的云端版本" }
        return remote(request("DELETE", slotPath(slot), revision = revision).second)
    }

    fun close() {
        token = null; challenge = null; jar.cookies = emptyList()
        client.dispatcher.cancelAll()
        client.connectionPool.evictAll()
    }

    fun logout() {
        try { if (token != null) request("POST", "api/auth/logout", "{}") }
        finally { close() }
    }

    private fun slotPath(slot: String): String {
        require(slot.matches(Regex("[a-zA-Z0-9_-]{1,64}"))) { "漫游槽位须为 1–64 个字母、数字、下划线或连字符" }
        return "api/auth/preferences/$slot"
    }

    private fun remote(body: JSONObject): RemotePreferences {
        val revision = body.getLong("revision")
        require(revision >= 0) { "无效的云端版本" }
        val envelope = body.optJSONObject("envelope")?.toString()
        if (envelope != null) PreferencesEnvelope.inspect(envelope)
        return RemotePreferences(revision, body.optLong("updated_at"), envelope, body.optBoolean("deleted"))
    }

    private fun request(method: String, path: String, content: String? = null, revision: Long? = null,
                        authenticated: Boolean = true, allowMissing: Boolean = false): Pair<Int, JSONObject> {
        val url = base.newBuilder().encodedPath(base.encodedPath.trimEnd('/') + "/" + path).build()
        val builder = Request.Builder().url(url).header("Accept", "application/json").header("User-Agent", "sb-easy-android/preferences")
        if (authenticated) builder.header("Authorization", "Bearer ${requireNotNull(token) { "请先登录中心账户" }}")
        if (revision != null) builder.header("If-Match", "\"$revision\"")
        val requestBody = content?.toRequestBody("application/json; charset=utf-8".toMediaType())
        builder.method(method, requestBody)
        client.newCall(builder.build()).execute().use { response ->
            when {
                response.code == 409 -> throw IllegalStateException("云端已被其他设备更新，请重新读取并比较；本次没有覆盖云端")
                response.code == 401 -> { token = null; throw IllegalStateException("登录或验证失败，或会话已过期") }
                response.code == 403 -> throw IllegalStateException("中心拒绝访问，请检查账户权限或 MFA 登录状态")
                response.code == 404 && allowMissing -> return response.code to JSONObject()
                !response.isSuccessful -> throw IllegalStateException("中心请求失败：HTTP ${response.code}")
            }
            val body = requireNotNull(response.body) { "中心返回空响应" }
            val maximum = PreferencesEnvelope.MAX_BYTES + 4096L
            require(body.contentLength() <= maximum) { "中心响应过大" }
            val source = body.source(); val buffer = okio.Buffer()
            while (buffer.size <= maximum) {
                if (source.read(buffer, minOf(8192L, maximum + 1L - buffer.size)) == -1L) break
            }
            require(buffer.size <= maximum) { "中心响应过大" }
            return response.code to JSONObject(PreferencesEnvelope.utf8(buffer.readByteArray()))
        }
    }
}
