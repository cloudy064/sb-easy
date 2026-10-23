package io.sbeasy.android.core

import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.*
import org.junit.Test

class ManagedTransportPolicyTest {
    @Test fun onlyExplicitLiteralLocalHttpIsAllowedAndEnrollmentResponseCannotMoveCredentials() {
        for (server in listOf("http://127.0.0.1:80", "http://10.2.3.4", "http://172.16.0.1", "http://192.168.1.1", "http://[::1]", "http://[fd01::1234]")) {
            assertThrows(IllegalArgumentException::class.java) { ManagedTransportPolicy.normalizeServer(server) }
            assertTrue(server, ManagedTransportPolicy.canAllowLocalHttp(server))
        }
        for (server in listOf("http://localhost", "http://local.test", "http://8.8.8.8", "http://169.254.169.254", "http://172.32.0.1", "http://[fe80::1]", "http://[2001:db8::1]", "http://127.1", "http://2130706433", "http://0177.0.0.1")) {
            assertFalse(server, ManagedTransportPolicy.canAllowLocalHttp(server))
        }
        for (server in listOf("https://user@panel.example", "https://@panel.example", "https://panel.example?token=secret", "https://panel.example#secret", "https://panel.example\\@other.example", "https://panel.example/a\nb")) {
            assertThrows(server, IllegalArgumentException::class.java) { ManagedTransportPolicy.normalizeServer(server) }
        }
        assertEquals("https://panel.example/sb", ManagedTransportPolicy.returnedServer("https://panel.example/sb/", "https://PANEL.example:443/sb", false))
        for (returned in listOf("http://panel.example/sb", "https://other.example/sb", "https://panel.example:8443/sb", "https://panel.example/other")) {
            assertThrows(IllegalArgumentException::class.java) { ManagedTransportPolicy.returnedServer("https://panel.example/sb", returned, true) }
        }
        assertFalse(Enrollment("http://127.0.0.1", "id", "name", "secret", "profile", "profile").allowInsecureLocalHttp)
    }

    @Test fun explicitLoopbackExceptionSendsOnlyAfterConsentAndDoesNotFollowRedirect() {
        val source = MockWebServer().apply { start() }
        val destination = MockWebServer().apply { start() }
        try {
            val base = source.url("/").newBuilder().host("127.0.0.1").build().toString()
            val transport = ManagedControlTransport()
            assertThrows(IllegalArgumentException::class.java) { transport.request(base, "/api/agent/config") }
            assertEquals(0, source.requestCount)
            source.enqueue(MockResponse().setBody("{}"))
            transport.execute(transport.request(base, "/api/agent/config", true).header("Authorization", "Bearer local-secret").build()).use { assertEquals(200, it.code) }
            assertEquals("Bearer local-secret", source.takeRequest().getHeader("Authorization"))
            source.enqueue(MockResponse().setResponseCode(307).addHeader("Location", destination.url("/copied")))
            assertThrows(IllegalArgumentException::class.java) {
                transport.execute(transport.request(base, "/api/devices/enroll", true).post("private-code".toRequestBody()).build())
            }
            assertEquals("private-code", source.takeRequest().body.readUtf8())
            assertEquals(0, destination.requestCount)
            assertThrows(IllegalArgumentException::class.java) {
                transport.execute(okhttp3.Request.Builder().url(base + "api/agent/config").header("Authorization", "Bearer copied-token").build())
            }
            assertEquals(2, source.requestCount)
        } finally { source.shutdown(); destination.shutdown() }
    }

    @Test fun realTlsRejectsUnknownCertificateAndAllRedirectDestinationsWithoutForwardingBodyOrToken() {
        val certificate = HeldCertificate.Builder().commonName("localhost").addSubjectAlternativeName("localhost").build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val clientTls = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        val source = MockWebServer().apply { useHttps(serverTls.sslSocketFactory(), false); start() }
        val destination = MockWebServer().apply { start() }
        val trusted = ManagedControlTransport(OkHttpClient.Builder().sslSocketFactory(clientTls.sslSocketFactory(), clientTls.trustManager).build())
        val base = source.url("/").toString()
        try {
            assertTrue(runCatching { ManagedControlTransport().execute(trusted.request(base, "/api/devices/enroll").post("one-use".toRequestBody()).build()) }.isFailure)
            assertEquals(0, source.requestCount)
            source.enqueue(MockResponse().setBody("{}"))
            trusted.execute(trusted.request(base, "/api/agent/config").header("Authorization", "Bearer protected").build()).use { assertEquals(200, it.code) }
            assertEquals("Bearer protected", source.takeRequest().getHeader("Authorization"))
            for (target in listOf(destination.url("/downgrade").toString(), source.url("/same-origin").toString(), "https://unrelated.invalid/steal")) {
                source.enqueue(MockResponse().setResponseCode(302).addHeader("Location", target))
                assertThrows(IllegalArgumentException::class.java) {
                    trusted.execute(trusted.request(base, "/api/devices/enroll").post("private-one-use-code".toRequestBody()).build())
                }
                assertEquals("private-one-use-code", source.takeRequest(2, TimeUnit.SECONDS)!!.body.readUtf8())
            }
            assertEquals(4, source.requestCount); assertEquals(0, destination.requestCount)
        } finally { source.shutdown(); destination.shutdown() }
    }
}
