package io.sbeasy.android.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class HttpDebugRoutingTest {
    private val secret = "a".repeat(64)
    private val source = """{"inbounds":[{"type":"tun","tag":"vpn","address":["172.19.0.1/30"]}],
      "outbounds":[{"type":"direct","tag":"direct"},{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":9000}],
      "endpoints":[{"type":"wireguard","tag":"private-wg"}],
      "route":{"final":"proxy","rules":[{"action":"sniff"},{"protocol":"dns","action":"hijack-dns"},
      {"domain":["center.example"],"outbound":"direct"},{"ip_cidr":["10.0.0.0/8"],"outbound":"private-wg"},
      {"package_name":["com.example.fixed"],"outbound":"proxy"},{"ip_is_private":true,"outbound":"direct"},
      {"domain_suffix":["example.com"],"outbound":"proxy"}]}}"""

    @After fun stopSession() { CaptureSession.end() }

    @Test fun sessionOptInNeverResurrectsLegacyPreferencesOrUploadsStandalone() {
        val saved = CaptureConfig(enabled = true, domains = listOf("example.com"), autoUpload = true)
        CaptureSession.end()
        assertFalse(CaptureSession.effective(saved, true).enabled)
        assertFalse(CaptureSession.effective(saved, true).autoUpload)
        assertTrue(runCatching { CaptureSession.requireEnabled() }.isFailure)
        CaptureSession.authorize()
        assertTrue(CaptureSession.effective(saved, true).enabled)
        assertTrue(CaptureSession.effective(saved, true).autoUpload)
        assertTrue(CaptureSession.effective(saved, false).enabled)
        assertFalse(CaptureSession.effective(saved, false).autoUpload)
        CaptureSession.end()
        assertFalse(CaptureSession.effective(saved, true).enabled)
    }

    @Test fun bothLoopbackLegsRequireCredentialsAndReturnLegCannotRecapture() {
        val root = JSONObject(HttpDebugRouting.apply(source, listOf("example.com"), secret))
        val upstream = objects(root.getJSONArray("inbounds")).single { it.optString("tag") == "sb-httpdebug-upstream" }
        assertEquals("127.0.0.1", upstream.getString("listen"))
        assertEquals(secret, upstream.getJSONArray("users").getJSONObject(0).getString("password"))
        val outbound = objects(root.getJSONArray("outbounds")).single { it.optString("tag") == "sb-httpdebug-engine" }
        assertEquals(secret, outbound.getString("password"))
        assertEquals("127.0.0.1", outbound.getString("server"))
        val captures = objects(root.getJSONObject("route").getJSONArray("rules")).filter { it.optString("outbound") == "sb-httpdebug-engine" || it.optString("action") == "reject" }
        assertEquals(2, captures.size)
        assertTrue(captures.all { it.getJSONArray("inbound").toString() == "[\"vpn\"]" })
        assertFalse(source.contains(secret))
    }

    @Test fun managementWireguardPrivateAndApplicationExitsPrecedeInterception() {
        val rules = objects(JSONObject(HttpDebugRouting.apply(source, listOf("example.com"), secret)).getJSONObject("route").getJSONArray("rules"))
        val capture = rules.indexOfFirst { it.optString("outbound") == "sb-httpdebug-engine" }
        for (field in listOf("domain", "ip_cidr", "package_name", "ip_is_private")) {
            assertTrue("$field changed priority", rules.indexOfFirst { it.has(field) } in 0 until capture)
        }
        assertEquals("proxy", rules.last().getString("outbound"))
        assertEquals("example.com", rules.last().getJSONArray("domain_suffix").getString(0))
    }

    @Test fun invalidDomainsSecretsAndReservedTagsAreRejected() {
        assertTrue(runCatching { HttpDebugRouting.normalize("https://example.com/path") }.isFailure)
        assertTrue(runCatching { HttpDebugRouting.normalize("example..com") }.isFailure)
        assertTrue(runCatching { HttpDebugRouting.apply(source, listOf("example.com"), "short") }.isFailure)
        val overlaid = HttpDebugRouting.apply(source, listOf("example.com"), secret)
        assertTrue(runCatching { HttpDebugRouting.apply(overlaid, listOf("example.com"), secret) }.isFailure)
    }

    private fun objects(array: JSONArray) = (0 until array.length()).map { array.getJSONObject(it) }
}
