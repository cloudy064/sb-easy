package io.sbeasy.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConfigInspectorTest {
    @Test
    fun describesRulesAndRedactsCredentials() {
        val summary = ConfigInspector.inspect(
            """
            {
              "dns": {"servers": [{"tag": "dns"}]},
              "inbounds": [{"type": "tun"}],
              "outbounds": [
                {"type": "shadowsocks", "tag": "Tokyo", "password": "secret"},
                {"type": "direct", "tag": "direct"}
              ],
              "route": {
                "rules": [{"domain_suffix": ["example.com"], "outbound": "Tokyo"}],
                "final": "direct"
              }
            }
            """.trimIndent(),
        )

        assertEquals(listOf("tun"), summary.inboundTypes)
        assertEquals(1, summary.dnsServers)
        assertEquals("direct", summary.routeFinal)
        assertTrue(summary.routeRules.single().contains("example.com"))
        assertTrue(summary.routeRules.single().contains("Tokyo"))
        assertTrue(summary.sanitizedJson.contains("password"))
        assertFalse(summary.sanitizedJson.contains("secret"))
    }
}
