package io.sbeasy.android.core

import org.junit.Assert.*
import org.junit.Test

class CaptureConfigTest {
    @Test fun normalizesAndRoundTrips() {
        val c = CaptureConfig(enabled = true, packages = listOf("com.example.app"), domains = listOf("EXAMPLE.COM."), hosts = listOf("API.EXAMPLE.COM", "2001:db8::1"), autoUpload = true).validated()
        assertEquals(listOf("example.com"), c.domains)
        assertEquals(listOf("api.example.com", "2001:db8::1"), c.hosts)
        assertEquals(c, CaptureConfig.parse(c.json().toString()))
    }
    @Test fun refusesUnboundedAndAmbiguousCapture() {
        for (c in listOf(CaptureConfig(enabled = true), CaptureConfig(fileKB = 1024), CaptureConfig(quotaMB = 0),
            CaptureConfig(domains = listOf("*.example.com")), CaptureConfig(hosts = listOf("https://example.com")),
            CaptureConfig(hosts = listOf("example.com:8080")), CaptureConfig(domains = listOf("1.2.3.4")))) {
            assertTrue(runCatching { c.validated() }.isFailure)
        }
    }
    @Test fun defaultIsOptIn() {
        val c = CaptureConfig.parse("{}")
        assertFalse(c.enabled); assertFalse(c.autoUpload); assertTrue(c.wifiOnly); assertFalse(c.deleteAfterUpload)
    }
}
