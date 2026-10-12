package io.sbeasy.android.core

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class HttpDebugRoutingTest {
    private val source = """{"inbounds":[{"type":"tun","tag":"vpn"}],"outbounds":[{"type":"direct","tag":"normal"}],"route":{"rules":[{"domain_suffix":["example.com"],"outbound":"normal"}],"final":"normal"}}"""
    @Test fun interceptsOnlyTunAndKeepsUpstreamOnExistingRouting() {
        val result = JSONObject(HttpDebugRouting.apply(source, listOf("example.com"), "a".repeat(64)))
        val rules = result.getJSONObject("route").getJSONArray("rules")
        assertEquals("sniff", rules.getJSONObject(0).getString("action"))
        assertEquals("reject", rules.getJSONObject(1).getString("action"))
        assertEquals("udp", rules.getJSONObject(1).getString("network"))
        assertEquals("vpn", rules.getJSONObject(2).getJSONArray("inbound").getString(0))
        assertEquals("sb-httpdebug-engine", rules.getJSONObject(2).getString("outbound"))
        assertEquals("normal", rules.getJSONObject(3).getString("outbound"))
        assertEquals("127.0.0.1", result.getJSONArray("inbounds").getJSONObject(1).getString("listen"))
        assertFalse(source.contains("sb-httpdebug"))
    }
    @Test fun domainValidationRejectsUrlsAndEmptyTargets() {
        listOf("", "https://example.com", "*.example.com", "example.com/path", ".com").forEach {
            assertThrows(IllegalArgumentException::class.java) { HttpDebugRouting.normalize(it) }
        }
        assertEquals(listOf("example.com", "other.example"), HttpDebugRouting.normalize("EXAMPLE.COM, example.com\nother.example"))
    }
    @Test fun preventsNestedCaptureAndRequiresTun() {
        val result = HttpDebugRouting.apply(source, listOf("example.com"), "b".repeat(64))
        assertThrows(IllegalArgumentException::class.java) { HttpDebugRouting.apply(result, listOf("example.com"), "b".repeat(64)) }
        assertThrows(IllegalArgumentException::class.java) { HttpDebugRouting.apply(source.replace("\"tun\"", "\"mixed\""), listOf("example.com"), "b".repeat(64)) }
    }
}
