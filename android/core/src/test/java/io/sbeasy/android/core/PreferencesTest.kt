package io.sbeasy.android.core

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.ByteString.Companion.decodeBase64
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class PreferencesTest {
    private fun vector() = JSONObject(java.io.File(System.getProperty("sb.testdata"), "preferences-v1.json").readText())

    @Test fun unicodeWebCryptoFixtureDecryptsAndMatchesByteForByte() {
        val fixture = vector(); val envelope = fixture.getJSONObject("envelope"); val password = fixture.getString("passphrase").toCharArray()
        val plain = PreferencesEnvelope.decrypt(envelope.toString(), password)
        assertEquals(fixture.getJSONObject("payload").toString(), JSONObject(plain).toString())
        val encrypted = JSONObject(PreferencesEnvelope.encrypt(plain, password, envelope.getString("salt").decodeBase64()!!.toByteArray(), envelope.getString("nonce").decodeBase64()!!.toByteArray()))
        assertEquals(envelope.getString("ciphertext"), encrypted.getString("ciphertext"))
        assertTrue(runCatching { PreferencesPayload.decode(plain) }.exceptionOrNull()?.message.orEmpty().contains("其他平台"))
    }

    @Test fun wrongPasswordTamperingParametersAndOversizeAreRejected() {
        val fixture = vector(); val envelope = fixture.getJSONObject("envelope"); val password = fixture.getString("passphrase").toCharArray()
        assertTrue(runCatching { PreferencesEnvelope.decrypt(envelope.toString(), "wrong-password-2026".toCharArray()) }.isFailure)
        val tampered = JSONObject(envelope.toString()).put("ciphertext", "A" + envelope.getString("ciphertext").drop(1))
        assertTrue(runCatching { PreferencesEnvelope.decrypt(tampered.toString(), password) }.isFailure)
        for ((key, value) in listOf("version" to 2, "iterations" to 1, "kdf" to "pbkdf2-sha1", "nonce" to "AAAA", "salt" to "AAAA", "extra" to true)) {
            assertTrue(key, runCatching { PreferencesEnvelope.inspect(JSONObject(envelope.toString()).put(key, value).toString()) }.isFailure)
        }
        assertTrue(runCatching { PreferencesEnvelope.inspect(" ".repeat(PreferencesEnvelope.MAX_BYTES + 1)) }.isFailure)
        assertTrue(runCatching { PreferencesEnvelope.encrypt("{}", "short".toCharArray()) }.isFailure)
        assertTrue(runCatching { PreferencesEnvelope.utf8(byteArrayOf(0xc3.toByte(), 0x28)) }.isFailure)
    }

    @Test fun payloadCannotSmuggleDeviceRulesAndImportedAppExitConflictsAreVisible() {
        val nodes = SubscriptionParser.parse("trojan://secret@proxy.example:443#One").nodes.map(JSONObject::toString)
        val sub = LocalSubscription("id-001", "Remote", "https://example/sub?token=local-secret", true, nodes = nodes)
        val base = SubscriptionParser.baseConfig(listOf(sub))
        val policy = LocalRouting.defaults(base.content)
        val encoded = PreferencesPayload.encode(PortablePreferences(listOf(sub), policy, null))
        assertFalse(encoded.contains("packages")); assertFalse(encoded.contains("include_official_app"))
        val parsed = PreferencesPayload.decode(encoded)
        assertEquals(sub.source, parsed.subscriptions.single().source)
        assertTrue(parsed.standaloneRouting!!.groups.all { it.packages.isEmpty() && !it.includeOfficialApp })
        val malicious = JSONObject(encoded)
        malicious.getJSONObject("preferences").getJSONObject("standalone_routing").getJSONArray("groups").getJSONObject(0).put("packages", org.json.JSONArray().put("com.other.app"))
        assertTrue(runCatching { PreferencesPayload.decode(malicious.toString()) }.isFailure)
        val changed = parsed.standaloneRouting.copy(groups = parsed.standaloneRouting.groups.map { it.copy(outbound = "direct") })
        assertTrue(runCatching { PreferencesPayload.retainDeviceRules(changed, policy) }.exceptionOrNull()?.message.orEmpty().contains("应用出口冲突"))
        val manual = sub.copy(remote = false, intervalMinutes = 0, source = "discarded-wireguard-private-key-and-scripts")
        val sanitized = PreferencesPayload.encode(PortablePreferences(listOf(manual), policy, null))
        assertFalse(sanitized.contains("discarded-wireguard"))
        assertEquals(nodes.size, SubscriptionParser.parse(PreferencesPayload.decode(sanitized).subscriptions.single().source).nodes.size)
    }

    @Test fun httpsLoginBindsMfaCookieAndSyncUsesCompareAndSwapIncludingTombstones() {
        val certificate = HeldCertificate.Builder().commonName("localhost").addSubjectAlternativeName("localhost").build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val clientTls = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        val server = MockWebServer().apply { useHttps(serverTls.sslSocketFactory(), false); start() }
        val transport = OkHttpClient.Builder().sslSocketFactory(clientTls.sslSocketFactory(), clientTls.trustManager).build()
        val client = PreferencesSyncClient(server.url("/").toString(), transport)
        val envelope = vector().getJSONObject("envelope")
        fun response(revision: Int, deleted: Boolean = false) = JSONObject().put("revision", revision).put("updated_at", 1234)
            .put("envelope", if (deleted) JSONObject.NULL else envelope).put("deleted", deleted).toString()
        try {
            server.enqueue(MockResponse().setBody("{\"mfa_required\":true,\"challenge\":\"one-use\"}").addHeader("Set-Cookie", "sb_auth_flow=bound; Path=/api/auth/; Secure; HttpOnly"))
            assertTrue(client.login("person", "account-password"))
            val login = server.takeRequest(); assertEquals("/api/auth/login", login.path); assertNull(login.getHeader("Authorization"))
            server.enqueue(MockResponse().setBody("{\"token\":\"account-session\"}"))
            client.completeMfa("123456")
            val mfa = server.takeRequest(); assertEquals("/api/auth/login/mfa", mfa.path); assertEquals("sb_auth_flow=bound", mfa.getHeader("Cookie")); assertNull(mfa.getHeader("Authorization"))
            server.enqueue(MockResponse().setResponseCode(404)); assertEquals(0, client.get("android-personal").revision)
            val get = server.takeRequest(); assertEquals("Bearer account-session", get.getHeader("Authorization")); assertNull(get.getHeader("Cookie"))
            server.enqueue(MockResponse().setBody(response(1))); assertEquals(1, client.put("android-personal", 0, envelope.toString()).revision)
            val put = server.takeRequest(); assertEquals("PUT", put.method); assertEquals("\"0\"", put.getHeader("If-Match")); assertEquals(envelope.toString(), JSONObject(put.body.readUtf8()).toString())
            server.enqueue(MockResponse().setResponseCode(409)); assertTrue(runCatching { client.put("android-personal", 0, envelope.toString()) }.exceptionOrNull()?.message.orEmpty().contains("没有覆盖")); server.takeRequest()
            server.enqueue(MockResponse().setBody(response(2, true))); val deleted = client.delete("android-personal", 1)
            assertTrue(deleted.deleted); assertNull(deleted.envelope); assertEquals(2, deleted.revision)
            assertEquals("\"1\"", server.takeRequest().getHeader("If-Match"))
            server.enqueue(MockResponse().setBody(response(3))); assertEquals(3, client.put("android-personal", deleted.revision, envelope.toString()).revision)
            assertEquals("\"2\"", server.takeRequest().getHeader("If-Match"))
            server.enqueue(MockResponse().setBody("{\"ok\":true}")); client.logout()
            assertEquals("/api/auth/logout", server.takeRequest().path); assertFalse(client.authenticated)
            assertTrue(runCatching { client.get("android-personal") }.isFailure)
            assertTrue(runCatching { PreferencesSyncClient("http://example.test") }.isFailure)
        } finally { client.close(); server.shutdown() }
    }
}
