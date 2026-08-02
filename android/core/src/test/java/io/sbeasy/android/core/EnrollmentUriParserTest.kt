package io.sbeasy.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class EnrollmentUriParserTest {
    private val code = "A1".repeat(32)

    @Test
    fun parsesServerGeneratedEnrollmentUri() {
        val target = EnrollmentUriParser.parse(
            "sbeasy://enroll?server=http%3A%2F%2F39.108.98.208%3A51821&code=$code",
        )

        assertEquals("http://39.108.98.208:51821", target.first)
        assertEquals(code.lowercase(), target.second)
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
}
