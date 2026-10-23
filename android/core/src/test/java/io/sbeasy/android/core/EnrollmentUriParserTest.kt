package io.sbeasy.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class EnrollmentUriParserTest {
    private val code = "A1".repeat(32)

    @Test
    fun parsesServerGeneratedEnrollmentUri() {
        val target = EnrollmentUriParser.parse(
            "sbeasy://enroll?server=https%3A%2F%2Fpanel.example.com%3A51821&code=$code",
        )

        assertEquals("https://panel.example.com:51821", target.first)
        assertEquals(code.lowercase(), target.second)
    }

    @Test fun localHttpRequiresExplicitAuthorizationAndPublicHttpCannotOptIn() {
        val local = "sbeasy://enroll?server=http%3A%2F%2F192.168.50.1%3A51821&code=$code"
        assertThrows(IllegalArgumentException::class.java) { EnrollmentUriParser.parse(local) }
        assertEquals("http://192.168.50.1:51821", EnrollmentUriParser.inspect(local).first)
        assertEquals("http://192.168.50.1:51821", EnrollmentUriParser.parse(local, true).first)
        for (address in listOf("http://39.108.98.208", "http://panel.example.com", "http://localhost", "http://169.254.169.254")) {
            assertThrows(IllegalArgumentException::class.java) { EnrollmentUriParser.normalizeServer(address, true) }
        }
    }

    @Test
    fun acceptsScannerWrappersAndUrlPrefix() {
        val target = EnrollmentUriParser.parse(
            "  \"URL:SBEASY://ENROLL?server=https%3A%2F%2Fpanel.example.com%2Fsb-easy%2F&code=$code\"  ",
        )

        assertEquals("https://panel.example.com/sb-easy", target.first)
        assertEquals(code.lowercase(), target.second)
    }

    @Test
    fun rejectsGenericQrCodesAndMalformedEnrollmentCodes() {
        assertThrows(IllegalArgumentException::class.java) {
            EnrollmentUriParser.parse("https://example.com/")
        }
        assertThrows(IllegalArgumentException::class.java) {
            EnrollmentUriParser.parse(
                "sbeasy://enroll?server=https%3A%2F%2Fpanel.example.com&code=short",
            )
        }
    }

    @Test
    fun rejectsWireGuardAndSingBoxConfigurationQrCodes() {
        assertThrows(IllegalArgumentException::class.java) {
            EnrollmentUriParser.parse(
                """[Interface]
PrivateKey = example
Address = 10.59.32.4/24

[Peer]
PublicKey = example
Endpoint = vpn.example.com:51820""",
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            EnrollmentUriParser.parse(
                "sing-box://import-remote-profile?url=https%3A%2F%2Fexample.com%2Fprofile.json",
            )
        }
    }
}
