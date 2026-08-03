package io.sbeasy.android.core

import org.junit.Assert.assertFalse
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
}
