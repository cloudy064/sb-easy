package io.sbeasy.android.core

import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.*
import org.junit.Test

class AppUpdateTransferTest {
    private fun transport(server: MockWebServer): AppUpdateTransfer {
        val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        val service = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val client = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        server.useHttps(service.sslSocketFactory(), false)
        return AppUpdateTransfer(OkHttpClient.Builder().sslSocketFactory(client.sslSocketFactory(), client.trustManager).build())
    }
    @Test fun httpsBoundedDownloadChecksDigestAndNeverFollowsRedirects() = runBlocking {
        val server = MockWebServer(); val transfer = transport(server); server.start()
        val folder = kotlin.io.path.createTempDirectory("sb-app-transfer-").toFile()
        val committed = File(folder, "app.apk").apply { writeText("existing verified cache") }; val part = File(folder, "download.part")
        val bytes = "new signed artifact".toByteArray()
        val release = AppCatalogTest.release().copy(url = server.url("/app.apk").toString(), bytes = bytes.size.toLong(), sha256 = PluginCatalog.sha256(bytes))
        try {
            server.enqueue(MockResponse().setBody(String(bytes)))
            transfer.artifact(release, part); assertArrayEquals(bytes, part.readBytes()); assertEquals("existing verified cache", committed.readText())
            assertEquals("/app.apk", server.takeRequest(1, TimeUnit.SECONDS)?.path)
            for (response in listOf(MockResponse().setResponseCode(302).setHeader("Location", server.url("/elsewhere")),
                MockResponse().setChunkedBody("too much content for a signed artifact size", 3),
                MockResponse().setChunkedBody("short", 2), MockResponse().setBody("x".repeat(bytes.size)))) {
                server.enqueue(response)
                assertTrue(runCatching { transfer.artifact(release, part) }.isFailure)
                assertFalse(part.exists()); assertEquals("existing verified cache", committed.readText())
                assertEquals("/app.apk", server.takeRequest(1, TimeUnit.SECONDS)?.path)
                assertNull(server.takeRequest(20, TimeUnit.MILLISECONDS))
            }
            assertTrue(runCatching { transfer.artifact(release.copy(url = "http://localhost/app.apk"), part) }.isFailure)
        } finally { server.shutdown(); folder.deleteRecursively() }
    }
    @Test fun catalogRejectsUntrustedTlsOversizeAndHttpRedirect() {
        val server = MockWebServer(); val transfer = transport(server); server.start()
        try {
            server.enqueue(MockResponse().setBody("{\"ok\":true}"))
            assertEquals("{\"ok\":true}", transfer.catalog(server.url("/catalog").toString()))
            server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", "http://example.test/catalog"))
            assertTrue(runCatching { transfer.catalog(server.url("/catalog").toString()) }.isFailure)
            server.enqueue(MockResponse().setChunkedBody(" ".repeat(PluginCatalog.MAX_ENVELOPE + 1), 8192))
            assertTrue(runCatching { transfer.catalog(server.url("/catalog").toString()) }.isFailure)
            val untrusted = AppUpdateTransfer()
            assertTrue(runCatching { untrusted.catalog(server.url("/catalog").toString()) }.isFailure)
            assertTrue(runCatching { transfer.catalog("https://user:password@example.test/catalog") }.isFailure)
        } finally { server.shutdown() }
    }
}
