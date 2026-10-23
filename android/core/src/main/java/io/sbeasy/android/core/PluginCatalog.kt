package io.sbeasy.android.core

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject

data class PluginRelease(
    val id: String, val platform: String, val version: String, val build: Long, val abi: String, val api: Int,
    val minHost: String, val maxHost: String, val minCore: String, val maxCore: String, val minOs: Int,
    val url: String, val sha256: String, val bytes: Long, val packageName: String, val signerSha256: String, val permissions: List<String>,
) {
    val revocationKey get() = "$platform/$id/$build"
    fun compatible(host: String, core: String, hostApi: Int, os: Int, abis: List<String>): Boolean =
        api == hostApi && minOs <= os && abi in abis && PluginCatalog.inRange(host, minHost, maxHost) && PluginCatalog.inRange(core, minCore, maxCore)
}
data class PluginRevocation(val id: String, val platform: String, val build: Long, val reason: String) {
    val key get() = "$platform/$id/$build"
}
data class VerifiedPluginCatalog(
    val sequence: Long, val issuedAt: Long, val expiresAt: Long, val releases: List<PluginRelease>,
    val revocations: List<PluginRevocation>, val payloadSha256: String, val envelope: String,
) {
    fun fresh(now: Long = System.currentTimeMillis() / 1000) = issuedAt <= now + 300 && expiresAt > now
}

object PluginCatalog {
    const val MAX_ENVELOPE = 1024 * 1024
    const val MAX_PAYLOAD = 512 * 1024
    const val MAX_ARTIFACT = 160L * 1024 * 1024
    private val identifier = Regex("[a-zA-Z0-9_-]{1,64}")
    private val version = Regex("(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})")
    private val hash = Regex("[0-9a-f]{64}")
    private val platforms = setOf("android", "windows", "linux", "macos")
    private val releaseFields = setOf("id", "platform", "version", "build", "abi", "api", "min_host", "max_host", "min_core", "max_core", "min_os", "url", "sha256", "bytes", "package", "signer_sha256", "permissions")

    fun trustedKeys(text: String, format: String = "sb-easy.plugin-catalog.keys"): Map<String, PublicKey> {
        require(text.toByteArray(Charsets.UTF_8).size <= 65536) { "目录公钥配置过大" }
        val root = StrictJson.objectValue(text)
        keys(root, setOf("format", "version", "keys"))
        require(root.opt("format") == format && integer(root, "version", 1, 1) == 1L) { "目录公钥格式不支持" }
        val values = root.getJSONObject("keys")
        require(values.length() <= 16) { "目录公钥数量过多" }
        return values.keys().asSequence().associateWith { name ->
            require(name.matches(identifier)) { "目录公钥 ID 无效" }
            val der = base64(values.getString(name))
            require(der.size in 1..1024) { "目录公钥长度无效" }
            val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der))
            require(key is RSAPublicKey && key.modulus.bitLength() in 2048..4096) { "目录仅支持 RSA 2048–4096 位公钥" }
            key
        }
    }

    fun verify(text: String, trusted: Map<String, PublicKey>, now: Long = System.currentTimeMillis() / 1000, requireFresh: Boolean = true): VerifiedPluginCatalog {
        val payload = signedPayload(text, trusted)
        val root = StrictJson.objectValue(PreferencesEnvelope.utf8(payload))
        keys(root, setOf("sequence", "issued_at", "expires_at", "releases", "revocations"))
        val sequence = integer(root, "sequence", 1, 9007199254740991)
        val issued = integer(root, "issued_at", 1, 4102444800)
        val expires = integer(root, "expires_at", 1, 4102444800)
        require(expires - issued in 1..90 * 86400L) { "目录有效期须在 90 天以内" }
        if (requireFresh) require(issued <= now + 300 && expires > now) { "目录已过期或尚未生效，请检查时间并刷新目录" }
        val releases = objects(root.getJSONArray("releases"), 128).map(::release)
        require(releases.map { "${it.platform}/${it.id}/${it.abi}/${it.build}" }.distinct().size == releases.size) { "目录含重复版本" }
        val revoked = objects(root.getJSONArray("revocations"), 256).map { row ->
            keys(row, setOf("id", "platform", "build", "reason"))
            PluginRevocation(id(row, "id"), platform(row), integer(row, "build", 1, 2100000000), string(row, "reason").also { reason ->
                require(reason.codePointCount(0, reason.length) in 1..240 && reason.none { it.code < 32 || it.code == 127 }) { "撤销说明无效" }
            })
        }
        require(revoked.map { it.key }.distinct().size == revoked.size) { "目录含重复撤销项" }
        return VerifiedPluginCatalog(sequence, issued, expires, releases, revoked, sha256(payload), text)
    }

    internal fun signedPayload(text: String, trusted: Map<String, PublicKey>, format: String = "sb-easy.plugin-catalog", prefix: ByteArray = byteArrayOf()): ByteArray {
        require(text.toByteArray(Charsets.UTF_8).size in 1..MAX_ENVELOPE) { "目录为空或超过 1 MiB" }
        val envelope = StrictJson.objectValue(text)
        keys(envelope, setOf("format", "version", "algorithm", "key_id", "payload", "signature"))
        require(envelope.opt("format") == format && integer(envelope, "version", 1, 1) == 1L && envelope.opt("algorithm") == "rsa-pss-sha256") { "不支持的目录签名格式" }
        val keyId = string(envelope, "key_id").also { require(it.matches(identifier)) { "目录密钥 ID 无效" } }
        val public = requireNotNull(trusted[keyId]) { "此目录签名密钥不在当前应用的受信任列表中" }
        require(public is RSAPublicKey && public.modulus.bitLength() in 2048..4096) { "无效的目录签名公钥" }
        val payload = base64(string(envelope, "payload")); val signed = base64(string(envelope, "signature"))
        require(payload.size in 1..MAX_PAYLOAD && signed.size in 256..512) { "目录签名或内容长度无效" }
        // Android API 23 uses the first name; the standard JDK uses the second.
        val verifier = runCatching { Signature.getInstance("SHA256withRSA/PSS") }.getOrElse { Signature.getInstance("RSASSA-PSS") }
        verifier.initVerify(public)
        verifier.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
        verifier.update(prefix)
        verifier.update(payload)
        require(verifier.verify(signed)) { "目录签名验证失败" }
        return payload
    }

    fun requireMonotonic(catalog: VerifiedPluginCatalog, previousSequence: Long, previousHash: String) {
        require(catalog.sequence >= previousSequence && (catalog.sequence != previousSequence || catalog.payloadSha256 == previousHash)) { "目录版本倒退或同版本内容发生变化，已保留已验证目录" }
    }

    fun inRange(current: String, minimum: String, maximum: String): Boolean = compare(current, minimum) >= 0 && compare(current, maximum) < 0
    private fun compare(a: String, b: String): Int {
        require(a.matches(version) && b.matches(version)) { "版本号须为三个数字段" }
        a.split('.').map(String::toInt).zip(b.split('.').map(String::toInt)).forEach { (left, right) -> if (left != right) return left.compareTo(right) }
        return 0
    }

    private fun release(row: JSONObject): PluginRelease {
        keys(row, releaseFields)
        val platform = platform(row)
        val name = string(row, "version").also { require(it.matches(version)) { "插件版本号无效" } }
        fun range(min: String, max: String) { require(compare(string(row, min), string(row, max)) < 0) { "插件兼容范围为空" } }
        range("min_host", "max_host"); range("min_core", "max_core")
        val rawUrl = string(row, "url")
        val url = rawUrl.toHttpUrlOrNull()
        require(rawUrl.length <= 4096 && rawUrl.startsWith("https://", ignoreCase = true) && rawUrl.none { it.isWhitespace() || it.code < 32 } &&
            url?.isHttps == true && url.username.isEmpty() && url.password.isEmpty() && url.fragment == null &&
            runCatching { java.net.URI(rawUrl).rawUserInfo == null }.getOrDefault(false)) { "插件下载必须使用不含账户信息的 HTTPS 地址" }
        val digest = string(row, "sha256").also { require(it.matches(hash)) { "插件摘要无效" } }
        val packageName = string(row, "package"); val signer = string(row, "signer_sha256")
        if (platform == "android") require(packageName.matches(Regex("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)+")) && signer.matches(hash)) { "Android 插件包名或签名无效" }
        else require(packageName.isEmpty() && signer.isEmpty()) { "此平台不能携带 Android 包信息" }
        val permissions = row.getJSONArray("permissions")
        require(permissions.length() <= 16) { "插件权限过多" }
        val capabilities = (0 until permissions.length()).map { index -> (permissions.get(index) as? String ?: error("插件权限无效")).also { require(it.matches(identifier)) { "插件权限无效" } } }
        require(capabilities.distinct().size == capabilities.size) { "插件权限重复" }
        return PluginRelease(id(row, "id"), platform, name, integer(row, "build", 1, 2100000000), id(row, "abi"), integer(row, "api", 1, 65535).toInt(),
            string(row, "min_host"), string(row, "max_host"), string(row, "min_core"), string(row, "max_core"), integer(row, "min_os", 0, 999999).toInt(),
            rawUrl, digest, integer(row, "bytes", 1, MAX_ARTIFACT), packageName, signer, capabilities)
    }

    fun sha256(data: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
    private fun platform(row: JSONObject) = string(row, "platform").also { require(it in platforms) { "目录平台无效" } }
    private fun id(row: JSONObject, name: String) = string(row, name).also { require(it.matches(identifier)) { "目录标识无效" } }
    private fun string(row: JSONObject, name: String) = row.opt(name) as? String ?: error("目录字段 $name 不是字符串")
    private fun integer(row: JSONObject, name: String, min: Long, max: Long): Long {
        val number = row.opt(name)
        require(number is Long && number in min..max) { "目录整数 $name 无效" }; return number
    }
    private fun base64(value: String): ByteArray {
        val result = value.decodeBase64()?.toByteArray() ?: error("目录 Base64 无效")
        require(result.toByteString().base64() == value) { "目录 Base64 必须使用规范编码" }; return result
    }
    private fun keys(row: JSONObject, expected: Set<String>) { require(row.keys().asSequence().toSet() == expected) { "目录含未知或缺少的字段" } }
    private fun objects(array: JSONArray, max: Int): List<JSONObject> {
        require(array.length() <= max) { "目录项目过多" }; return (0 until array.length()).map(array::getJSONObject)
    }
}
