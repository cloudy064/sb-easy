package io.sbeasy.android.core

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.ByteString.Companion.encodeUtf8
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class SubscriptionParserTest {
    private val uuid = "7cd0e302-6321-4e96-aa03-967c91724aa5"
    private val trojan = "trojan://secret@example.com:443?security=tls&sni=example.com#Example"

    @Test fun parsesShareLinksWithCredentialsAndRealTransport() {
        val result = SubscriptionParser.parse("vless://$uuid@example.com:8443?type=ws&path=%2Fproxy&host=edge.example&security=reality&pbk=key&sid=abcd#Name\n$trojan")
        assertEquals(2, result.nodes.size)
        assertEquals("/proxy", result.nodes[0].getJSONObject("transport").getString("path"))
        assertEquals("edge.example", result.nodes[0].getJSONObject("transport").getJSONObject("headers").getString("Host"))
        assertEquals("key", result.nodes[0].getJSONObject("tls").getJSONObject("reality").getString("public_key"))
        assertEquals("secret", result.nodes[1].getString("password"))
    }

    @Test fun base64SubscriptionAndBothShadowsocksEncodings() {
        val auth = "aes-256-gcm:pass:word".encodeUtf8().base64()
        val full = "aes-128-gcm:password@ss.example:8388".encodeUtf8().base64()
        val lines = "ss://$auth@ss.example:8388#中文\nss://$full#Full"
        val result = SubscriptionParser.parse(lines.encodeUtf8().base64())
        assertEquals("Base64", result.format)
        assertEquals("中文", result.nodes[0].getString("tag"))
        assertEquals("pass:word", result.nodes[0].getString("password"))
        assertEquals("ss.example", result.nodes[1].getString("server"))
    }

    @Test fun clashImportsNodesAndExplainsUnsupportedRowsWithoutCredentials() {
        val result = SubscriptionParser.parse("""
            proxies:
              - { name: First, type: trojan, server: one.example, port: 443, password: secret }
              - { name: Unsupported, type: ssr, server: two.example, port: 443, password: dont-leak-this }
              - name: Second
                type: vmess
                server: three.example
                port: 8443
                uuid: $uuid
                cipher: auto
                network: grpc
                grpc-opts: { grpc-service-name: proxy }
                tls: true
            rules: ["MATCH,DIRECT"]
        """.trimIndent())
        assertEquals(2, result.nodes.size)
        assertEquals(2, result.issues.single().index)
        assertFalse(result.issues.single().reason.contains("dont-leak-this"))
        assertEquals("proxy", result.nodes.last().getJSONObject("transport").getString("service_name"))
    }

    @Test fun rejectsYamlObjectTagsAndDuplicateKeys() {
        assertThrows(IllegalArgumentException::class.java) { SubscriptionParser.parse("proxies: !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader []]") }
        assertThrows(IllegalArgumentException::class.java) { SubscriptionParser.parse("proxies: []\nproxies: []") }
    }

    @Test fun skipsFileReferencesAndGroupsAndKeepsStableDuplicateNames() {
        val good = """{"type":"trojan","tag":"name","server":"proxy.example","server_port":443,"password":"secret"}"""
        val bad = JSONObject(good).put("tls", JSONObject().put("certificate_path", "/private/key")).toString()
        val result = SubscriptionParser.parse("""{"outbounds":[$good,$good,$bad,{"type":"selector","tag":"all"}]}""")
        assertEquals(listOf("name", "name (2)"), result.nodes.map { it.getString("tag") })
        assertEquals(2, result.issues.size)
        assertEquals(3, result.issues.first().index)
    }

    @Test fun entirelyUnsupportedImportCannotReplaceNodes() {
        assertThrows(IllegalArgumentException::class.java) { SubscriptionParser.parse("ssr://not-supported") }
        assertThrows(IllegalArgumentException::class.java) { SubscriptionParser.parse("[]") }
    }

    @Test fun baseConfigIsStandaloneIpv6AndNoFirstBootRuleDownloads() {
        val sub = LocalSubscription("11111111-2222-3333-4444-555555555555", "Example", trojan, false,
            nodes = SubscriptionParser.parse(trojan).nodes.map { it.toString() })
        val base = SubscriptionParser.baseConfig(listOf(sub))
        val rendered = JSONObject(LocalRouting.render(base.content, LocalRouting.defaults(base.content), includeGeoRules = false).content)
        assertFalse(rendered.toString().contains("https://cdn.jsdelivr.net"))
        assertFalse(rendered.toString().contains("geosite-cn"))
        assertTrue(rendered.getJSONArray("inbounds").getJSONObject(0).getJSONArray("address").toString().contains("fdfe:"))
        assertEquals(base.etag, SubscriptionParser.baseConfig(listOf(sub.copy(lastAttempt = 42))).etag)
        assertTrue(rendered.getJSONObject("route").getString("final").startsWith(LocalRouting.TAG_PREFIX))
        assertEquals(1, LocalRouting.availableNodes(rendered.toString()).size)
        System.getProperty("subscription.fixture.path")?.let { java.io.File(it).writeText(rendered.toString(2)) }
    }

    @Test fun quotasAndCadenceSurvivePersistence() {
        val quota = SubscriptionQuota.parse("upload=100; download=300; total=1000; expire=1750000000; invalid=unknown")
        assertEquals(600L, quota.remaining)
        assertTrue(quota.expired(1_750_000_001_000L))
        val source = LocalSubscription("id", "name", "https://example.com/token", true, intervalMinutes = 15,
            lastAttempt = 1000, quota = quota, issues = listOf(SubscriptionIssue(3, "unsupported")))
        val restored = LocalSubscription.fromJson(source.json())
        assertEquals(source, restored)
        assertFalse(restored.due(899_000))
        assertTrue(restored.due(901_000))
        assertTrue(restored.due(999)) // Clock correction cannot postpone updates forever.
        assertFalse(restored.copy(intervalMinutes = 0).due(Long.MAX_VALUE))
    }

    @Test fun subscriptionsRequireHttpsAndRejectEmbeddedBasicAuth() {
        assertThrows(IllegalArgumentException::class.java) { SubscriptionParser.subscriptionUrl("http://example.test/s", false) }
        assertThrows(IllegalArgumentException::class.java) { SubscriptionParser.subscriptionUrl("https://user:secret@example.test/s", false) }
        assertEquals("http://127.0.0.1/sub", SubscriptionParser.subscriptionUrl("http://127.0.0.1/sub", true))
    }

    @Test fun downloadHandlesShortBodiesHeadersAndRedirectsWithoutAuth() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "/final"))
            server.enqueue(MockResponse().setBody(trojan).setHeader("Subscription-Userinfo", "download=8; total=100"))
            server.start()
            val fetched = SubscriptionFetcher().fetch(server.url("/secret-token").toString(), true)
            assertEquals(trojan, fetched.content)
            assertEquals(92L, fetched.quota.remaining)
            repeat(2) { assertNull(server.takeRequest().getHeader("Authorization")) }
        }
    }

    @Test fun downloadRejectsOversizedChunkedResponsesAndHttpFailures() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setChunkedBody("x".repeat(SubscriptionParser.MAX_BYTES + 2), 8192))
            server.enqueue(MockResponse().setResponseCode(403).setBody("secret-error-text"))
            server.start()
            assertThrows(IllegalArgumentException::class.java) { SubscriptionFetcher().fetch(server.url("/a").toString(), true) }
            val error = assertThrows(IllegalArgumentException::class.java) { SubscriptionFetcher().fetch(server.url("/b").toString(), true) }
            assertFalse(error.message.orEmpty().contains("secret-error-text"))
        }
    }
}
