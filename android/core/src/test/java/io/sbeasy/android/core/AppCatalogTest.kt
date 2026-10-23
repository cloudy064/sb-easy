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

class AppCatalogTest {
    companion object {
        private val pair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        private val keys = mapOf("test-only" to pair.public)
        private const val now = 1792732800L
        fun release() = AppRelease("1.4.0", 29, 24, setOf("arm64-v8a"), "io.sbeasy.android", "a".repeat(64),
            "https://example.test/app.apk", "b".repeat(64), 100, "1.14.3", "c".repeat(40), "d".repeat(64))
    }
    private fun payload(seq: Long = 1): JSONObject {
        val r = release()
        return JSONObject().put("sequence", seq).put("issued_at", now - 60).put("expires_at", now + 3600)
            .put("releases", JSONArray().put(JSONObject().put("version", r.version).put("build", r.build).put("min_os", r.minOs).put("abis", JSONArray(r.abis))
                .put("package", r.packageName).put("signer_sha256", r.signer).put("url", r.url).put("sha256", r.sha256).put("bytes", r.bytes)
                .put("core_version", r.coreVersion).put("source_revision", r.sourceRevision).put("provenance_sha256", r.provenanceSha256)))
            .put("revocations", JSONArray().put(JSONObject().put("build", 1).put("reason", "撤销旧版")))
    }
    private fun sign(raw: String, domain: Boolean = true, salt: Int = 32, mgf: MGF1ParameterSpec = MGF1ParameterSpec.SHA256): String {
        val signer = Signature.getInstance("RSASSA-PSS"); signer.initSign(pair.private); signer.setParameter(PSSParameterSpec("SHA-256", "MGF1", mgf, salt, 1))
        if (domain) signer.update(AppCatalog.PREFIX)
        signer.update(raw.toByteArray(Charsets.UTF_8))
        return JSONObject().put("format", "sb-easy.app-catalog").put("version", 1).put("algorithm", "rsa-pss-sha256")
            .put("key_id", "test-only").put("payload", raw.toByteArray(Charsets.UTF_8).toByteString().base64()).put("signature", signer.sign().toByteString().base64()).toString()
    }
    @Test fun signatureDomainPssRawBytesAndIndependentTrustAreEnforced() {
        val raw = payload().toString(2)
        assertEquals(release(), AppCatalog.verify(sign(raw), keys, now).releases.single())
        for (signed in listOf(sign(raw, false), sign(raw, salt = 20), sign(raw, mgf = MGF1ParameterSpec.SHA1))) {
            assertTrue(runCatching { AppCatalog.verify(signed, keys, now) }.isFailure)
        }
        val reformatted = JSONObject(sign(raw)).put("payload", payload().toString().toByteArray().toByteString().base64()).toString()
        assertTrue(runCatching { AppCatalog.verify(reformatted, keys, now) }.isFailure)
        assertTrue(runCatching { AppCatalog.verify(sign(raw), emptyMap(), now) }.isFailure)
        val trust = JSONObject().put("format", "sb-easy.app-catalog.keys").put("version", 1).put("keys", JSONObject().put("test-only", pair.public.encoded.toByteString().base64()))
        assertEquals(pair.public, AppCatalog.trustedKeys(trust.toString())["test-only"])
        assertTrue(runCatching { PluginCatalog.trustedKeys(trust.toString()) }.isFailure)
    }
    @Test fun replayExpiryConflictingIdentityAndMalformedMetadataAreRejected() {
        val first = AppCatalog.verify(sign(payload().toString()), keys, now)
        val next = AppCatalog.verify(sign(payload(2).toString()), keys, now)
        AppCatalog.requireMonotonic(next, first); AppCatalog.requireMonotonic(first, first)
        assertTrue(runCatching { AppCatalog.requireMonotonic(first, next) }.isFailure)
        val changed = AppCatalog.verify(sign(payload().put("expires_at", now + 7200).toString()), keys, now)
        assertTrue(runCatching { AppCatalog.requireMonotonic(changed, first) }.isFailure)
        assertTrue(runCatching { AppCatalog.verify(first.envelope, keys, now + 3600) }.isFailure)
        assertFalse(AppCatalog.verify(first.envelope, keys, now + 3600, false).fresh(now + 3600))
        for ((name, value) in listOf("package" to "evil.app", "url" to "https://@example.test/app.apk", "url" to "https://example.test/app.apk#", "min_os" to 23, "build" to true, "source_revision" to "bad", "abis" to JSONArray(listOf("x86", "x86")), "extra" to 1)) {
            val p = payload(); p.getJSONArray("releases").getJSONObject(0).put(name, value)
            assertTrue(name, runCatching { AppCatalog.verify(sign(p.toString()), keys, now) }.isFailure)
        }
        assertTrue(runCatching { AppCatalog.verify(sign(payload().toString().dropLast(1) + ",\"sequence\":1}"), keys, now) }.isFailure)
        val p = payload(); p.getJSONArray("releases").put(JSONObject(p.getJSONArray("releases").getJSONObject(0).toString()).put("abis", JSONArray(listOf("x86_64"))).put("core_version", "1.14.2"))
        assertTrue(runCatching { AppCatalog.verify(sign(p.toString()), keys, now) }.isFailure)
    }
    @Test fun actualApkIdentityMustMatchSingleCurrentCertificateAndAllMetadata() {
        val expected = release(); val actual = AppArtifactIdentity(expected.packageName, expected.version, expected.build, expected.minOs, listOf(expected.signer), expected.abis, false)
        fun validate(value: AppArtifactIdentity) = AppPackagePolicy.validateIdentity(value, expected, expected.signer, 24, listOf("arm64-v8a"), false)
        validate(actual)
        for (invalid in listOf(actual.copy(packageName = "evil.app"), actual.copy(version = "1.3.4"), actual.copy(build = 28), actual.copy(minOs = 25),
            actual.copy(signers = listOf("b".repeat(64))), actual.copy(signers = listOf(expected.signer, expected.signer)), actual.copy(abis = setOf("x86")), actual.copy(debuggable = true))) {
            assertTrue(runCatching { validate(invalid) }.isFailure)
        }
        assertTrue(runCatching { AppPackagePolicy.validateIdentity(actual, expected, expected.signer, 23, listOf("arm64-v8a"), false) }.isFailure)
        assertTrue(runCatching { AppPackagePolicy.validateIdentity(actual, expected, expected.signer, 24, listOf("x86_64"), false) }.isFailure)
    }
    @Test fun pythonOpenSslPublisherInteroperatesWithAndroidVerifier() {
        val directory = System.getenv("SB_EASY_APP_CATALOG_FIXTURE")
        assumeTrue("Generate ephemeral app catalog fixtures", !directory.isNullOrEmpty())
        val folder = File(requireNotNull(directory)); val trust = AppCatalog.trustedKeys(File(folder, "keys.json").readText()); val expected = JSONObject(File(folder, "test-info.json").readText())
        val catalog = AppCatalog.verify(File(folder, "catalog.json").readText(), trust, expected.getLong("now"))
        assertEquals(expected.getLong("sequence"), catalog.sequence); assertEquals(expected.getString("payload_sha256"), catalog.payloadSha256)
        for (name in listOf("no-domain.json", "wrong-salt.json", "wrong-mgf.json")) assertTrue(name, runCatching { AppCatalog.verify(File(folder, name).readText(), trust, expected.getLong("now")) }.isFailure)
    }
}
