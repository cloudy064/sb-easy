package io.sbeasy.android.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ClientDiagnosticsTest {
    @Test
    fun redactsCredentialsFromCommonDiagnosticFormats() {
        val raw = """
            {"agent_token":"token-value","secret":"secret-value","uuid":"uuid-value"}
            Authorization: Bearer bearer-value
            sbeasy://enroll?server=https%3A%2F%2Fpanel&code=enroll-code
            vmess://userinfo@example.com:443
            PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
        """.trimIndent()

        val redacted = redactDiagnosticText(raw)

        listOf("token-value", "secret-value", "uuid-value", "bearer-value", "enroll-code", "userinfo")
            .forEach { secret -> assertFalse(redacted.contains(secret)) }
        assertTrue(redacted.contains("***"))
        assertTrue(redacted.contains("example.com:443"))
    }

    @Test
    fun reservesDiagnosticCapacityForAppNetworkLifecycleEvents() {
        val app = (1..900).map { "app-$it" }
        val libbox = (1..2_000).map { "libbox-$it" }
        val external = (1..500).map { "external-$it" }

        val merged = mergeDiagnosticLines(app, libbox, external, maxLines = 1_200)

        assertEquals(1_200, merged.size)
        assertTrue(merged.contains("app-900"))
        assertTrue(merged.contains("app-501"))
        assertFalse(merged.contains("app-500"))
        assertEquals(600, merged.count { it.startsWith("libbox-") })
        assertEquals(200, merged.count { it.startsWith("external-") })
    }
}
