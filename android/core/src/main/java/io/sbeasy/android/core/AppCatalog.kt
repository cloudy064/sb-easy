package io.sbeasy.android.core

import java.security.PublicKey
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONObject

data class AppRelease(val version: String, val build: Long, val minOs: Int, val abis: Set<String>, val packageName: String,
    val signer: String, val url: String, val sha256: String, val bytes: Long, val coreVersion: String,
    val sourceRevision: String, val provenanceSha256: String)
data class VerifiedAppCatalog(val sequence: Long, val issuedAt: Long, val expiresAt: Long, val releases: List<AppRelease>,
    val revocations: Map<Long, String>, val payloadSha256: String, val envelope: String) {
    fun fresh(now: Long = System.currentTimeMillis() / 1000) = issuedAt <= now + 300 && expiresAt > now
}

/** App and plugin signatures are separate domains even when a publisher reuses an RSA key. */
object AppCatalog {
    val PREFIX = "sb-easy.app-catalog/v1\n".toByteArray(Charsets.US_ASCII)
    val ABIS = setOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
    private val semver = Regex("(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})")
    private val hash = Regex("[0-9a-f]{64}")
    fun trustedKeys(text: String) = PluginCatalog.trustedKeys(text, "sb-easy.app-catalog.keys")
    fun verify(text: String, trusted: Map<String, PublicKey>, now: Long = System.currentTimeMillis() / 1000, requireFresh: Boolean = true): VerifiedAppCatalog {
        val payload = PluginCatalog.signedPayload(text, trusted, "sb-easy.app-catalog", PREFIX)
        val root = StrictJson.objectValue(PreferencesEnvelope.utf8(payload))
        fields(root, setOf("sequence", "issued_at", "expires_at", "releases", "revocations"))
        val sequence = integer(root, "sequence", 1, 9007199254740991)
        val issued = integer(root, "issued_at", 1, 4102444800); val expires = integer(root, "expires_at", 1, 4102444800)
        require(expires - issued in 1..90 * 86400L) { "目录有效期须在 90 天以内" }
        if (requireFresh) require(issued <= now + 300 && expires > now) { "应用目录已过期或尚未生效" }
        val rows = root.getJSONArray("releases"); require(rows.length() <= 128) { "应用目录版本过多" }
        val releases = (0 until rows.length()).map { index ->
            val row = rows.getJSONObject(index)
            fields(row, setOf("version", "build", "min_os", "abis", "package", "signer_sha256", "url", "sha256", "bytes", "core_version", "source_revision", "provenance_sha256"))
            val abis = row.getJSONArray("abis"); require(abis.length() in 1..4) { "APK 架构声明无效" }
            val architectures = (0 until abis.length()).map { abis.get(it) as? String ?: error("APK 架构无效") }
            require(architectures.distinct().size == architectures.size && architectures.all { it in ABIS }) { "APK 架构重复或不支持" }
            AppRelease(version(row, "version"), integer(row, "build", 1, 2100000000), integer(row, "min_os", 24, 999).toInt(), architectures.toSet(),
                string(row, "package").also { require(it == "io.sbeasy.android") { "目录包名不属于本应用" } }, digest(row, "signer_sha256"),
                https(string(row, "url")), digest(row, "sha256"), integer(row, "bytes", 1, PluginCatalog.MAX_ARTIFACT), version(row, "core_version"),
                string(row, "source_revision").also { require(it.matches(Regex("[0-9a-f]{40}"))) { "内核源码 revision 无效" } }, digest(row, "provenance_sha256"))
        }
        require(releases.map { it.build to it.abis }.distinct().size == releases.size) { "应用目录存在重复版本/架构" }
        // One build has one identity, including provenance. ABI-specific APK digests may differ.
        releases.groupBy { it.build }.values.forEach { group ->
            require(group.map { listOf(it.version, it.signer, it.coreVersion, it.sourceRevision, it.provenanceSha256, it.minOs.toString()) }.distinct().size == 1) { "同一构建声明了冲突的身份" }
        }
        val revoked = root.getJSONArray("revocations"); require(revoked.length() <= 256) { "撤销记录过多" }
        val records = (0 until revoked.length()).map { index ->
            val row = revoked.getJSONObject(index); fields(row, setOf("build", "reason"))
            integer(row, "build", 1, 2100000000) to string(row, "reason").also { reason ->
                require(reason.codePointCount(0, reason.length) in 1..240 && reason.none { it.code < 32 || it.code == 127 }) { "撤销说明无效" }
            }
        }
        require(records.map { it.first }.distinct().size == records.size) { "重复的撤销记录" }
        return VerifiedAppCatalog(sequence, issued, expires, releases, records.toMap(), PluginCatalog.sha256(payload), text)
    }
    fun requireMonotonic(next: VerifiedAppCatalog, previous: VerifiedAppCatalog) {
        require(next.sequence > previous.sequence || next.sequence == previous.sequence && next.payloadSha256 == previous.payloadSha256) { "应用目录序号倒退或同序号内容被替换" }
    }
    internal fun https(raw: String): String {
        val url = raw.toHttpUrlOrNull()
        require(raw.length <= 4096 && raw.startsWith("https://", true) && raw.none { it.isWhitespace() || it.code < 32 } &&
            url?.isHttps == true && url.username.isEmpty() && url.password.isEmpty() && url.fragment == null &&
            runCatching { java.net.URI(raw).rawUserInfo == null }.getOrDefault(false)) { "更新地址必须为不含账户信息的 HTTPS" }
        return raw
    }
    internal fun fields(row: JSONObject, expected: Set<String>) { require(row.keys().asSequence().toSet() == expected) { "应用更新信息含未知或缺失字段" } }
    internal fun string(row: JSONObject, name: String) = row.opt(name) as? String ?: error("字段 $name 不是字符串")
    internal fun integer(row: JSONObject, name: String, minimum: Long, maximum: Long): Long = (row.opt(name) as? Long)?.also { require(it in minimum..maximum) { "整数 $name 超出范围" } } ?: error("字段 $name 不是整数")
    internal fun digest(row: JSONObject, name: String) = string(row, name).also { require(it.matches(hash)) { "摘要 $name 无效" } }
    private fun version(row: JSONObject, name: String) = string(row, name).also { require(it.matches(semver)) { "版本号 $name 无效" } }
}
