package io.sbeasy.android.core

import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

class PluginCatalogTest {
    companion object {
        private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        private val keys = mapOf("test-only" to pair.public)
        private const val now = 1792732800L
    }
    private fun payload(sequence: Long = 1) = JSONObject().put("sequence", sequence).put("issued_at", now - 60).put("expires_at", now + 3600)
        .put("releases", JSONArray().put(JSONObject().put("id", "http-debug").put("platform", "android").put("version", "1.0.1").put("build", 2)
            .put("abi", "arm64-v8a").put("api", 2).put("min_host", "1.3.4").put("max_host", "2.0.0")
            .put("min_core", "1.14.0").put("max_core", "1.15.0").put("min_os", 24).put("url", "https://example.test/plugin.apk")
            .put("sha256", "a".repeat(64)).put("bytes", 128).put("package", "io.sbeasy.httpdebug").put("signer_sha256", "b".repeat(64))
            .put("permissions", JSONArray(listOf("internet", "private-files", "tls-intercept")))))
        .put("revocations", JSONArray().put(JSONObject().put("id", "http-debug").put("platform", "android").put("build", 1).put("reason", "旧版已撤销")))
    private fun sign(text: String, salt: Int = 32, mgf: MGF1ParameterSpec = MGF1ParameterSpec.SHA256): String {
        val signer = Signature.getInstance("RSASSA-PSS"); signer.initSign(pair.private)
        signer.setParameter(PSSParameterSpec("SHA-256", "MGF1", mgf, salt, 1))
        signer.update(text.toByteArray(Charsets.UTF_8))
        return JSONObject().put("format", "sb-easy.plugin-catalog").put("version", 1).put("algorithm", "rsa-pss-sha256")
            .put("key_id", "test-only").put("payload", text.toByteArray(Charsets.UTF_8).toByteString().base64())
            .put("signature", signer.sign().toByteString().base64()).toString()
    }

    @Test fun exactBytesPssAndCompatibilityRangesAreEnforced() {
        val raw = payload().toString(2)
        val catalog = PluginCatalog.verify(sign(raw), keys, now)
        val release = catalog.releases.single()
        assertTrue(release.compatible("1.3.4", "1.14.3", 2, 24, listOf("arm64-v8a")))
        for (host in listOf("1.3.3", "2.0.0")) assertFalse(release.compatible(host, "1.14.3", 2, 24, listOf("arm64-v8a")))
        assertFalse(release.compatible("1.3.4", "1.15.0", 2, 24, listOf("arm64-v8a")))
        assertFalse(release.compatible("1.3.4", "1.14.3", 1, 24, listOf("arm64-v8a")))
        assertFalse(release.compatible("1.3.4", "1.14.3", 2, 23, listOf("arm64-v8a")))
        assertFalse(release.compatible("1.3.4", "1.14.3", 2, 24, listOf("x86_64")))
        val modified = JSONObject(sign(raw)).put("payload", payload().toString().toByteArray().toByteString().base64()).toString()
        assertTrue(runCatching { PluginCatalog.verify(modified, keys, now) }.isFailure)
        assertTrue(runCatching { PluginCatalog.verify(sign(raw, 20), keys, now) }.isFailure)
        assertTrue(runCatching { PluginCatalog.verify(sign(raw, 32, MGF1ParameterSpec.SHA1), keys, now) }.isFailure)
        assertTrue(runCatching { PluginCatalog.verify(sign(raw), emptyMap(), now) }.isFailure)
        assertEquals("android/http-debug/1", catalog.revocations.single().key)
    }

    @Test fun sequenceExpiryAndMalformedSignedPayloadAreRejected() {
        val first = PluginCatalog.verify(sign(payload().toString()), keys, now)
        val next = PluginCatalog.verify(sign(payload(2).toString()), keys, now)
        PluginCatalog.requireMonotonic(next, first.sequence, first.payloadSha256)
        assertTrue(runCatching { PluginCatalog.requireMonotonic(first, next.sequence, next.payloadSha256) }.isFailure)
        val different = PluginCatalog.verify(sign(payload().put("expires_at", now + 7200).toString()), keys, now)
        assertTrue(runCatching { PluginCatalog.requireMonotonic(different, first.sequence, first.payloadSha256) }.isFailure)
        assertTrue(runCatching { PluginCatalog.verify(first.envelope, keys, now + 3600) }.isFailure)
        assertFalse(PluginCatalog.verify(first.envelope, keys, now + 3600, false).fresh(now + 3600))
        val duplicate = payload().toString().dropLast(1) + ",\"sequence\":1}"
        for (malformed in listOf(duplicate, payload().toString() + "{}", "{\"sequence\":NaN}", "{\"\\u+123\":0}")) {
            assertTrue(runCatching { PluginCatalog.verify(sign(malformed), keys, now) }.isFailure)
        }
        for ((field, value) in listOf("url" to "http://example.test/plugin.apk", "build" to true, "version" to "01.0.1", "extra" to "bad")) {
            val modified = payload(); modified.getJSONArray("releases").getJSONObject(0).put(field, value)
            assertTrue(field, runCatching { PluginCatalog.verify(sign(modified.toString()), keys, now) }.isFailure)
        }
    }

    @Test fun trustFileCannotInjectAnUnknownKeyAndRejectsSmallRsaKeys() {
        val encoded = JSONObject().put("format", "sb-easy.plugin-catalog.keys").put("version", 1)
            .put("keys", JSONObject().put("test-only", pair.public.encoded.toByteString().base64())).toString()
        assertEquals(pair.public, PluginCatalog.trustedKeys(encoded)["test-only"])
        val small = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val invalid = JSONObject(encoded).put("keys", JSONObject().put("weak", small.public.encoded.toByteString().base64())).toString()
        assertTrue(runCatching { PluginCatalog.trustedKeys(invalid) }.isFailure)
        assertTrue(runCatching { PluginCatalog.verify(" ".repeat(PluginCatalog.MAX_ENVELOPE + 1), keys, now) }.isFailure)
    }

    @Test fun sharedOpenSslFixtureUsesTheSameSignatureAndRawPayload() {
        val location = System.getenv("SB_EASY_PLUGIN_CATALOG_FIXTURE")
        assumeTrue("Generate the ephemeral-key OpenSSL fixtures to run interoperability checks", !location.isNullOrBlank())
        val folder = File(requireNotNull(location))
        val trust = PluginCatalog.trustedKeys(File(folder, "keys.json").readText())
        val expected = JSONObject(File(folder, "test-info.json").readText())
        val catalog = PluginCatalog.verify(File(folder, "catalog.json").readText(), trust, expected.getLong("now"))
        assertEquals(expected.getLong("sequence"), catalog.sequence)
        assertEquals(expected.getString("payload_sha256"), catalog.payloadSha256)
        for (name in listOf("wrong-salt.json", "wrong-mgf.json", "duplicate-key.json")) {
            assertTrue(name, runCatching { PluginCatalog.verify(File(folder, name).readText(), trust, expected.getLong("now")) }.isFailure)
        }
    }
}
