package io.sbeasy.android.core

import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlinx.coroutines.*
import okhttp3.Dns
import okhttp3.OkHttpClient
import org.junit.Assert.*
import org.junit.Test

class ConnectivityProbeTest {
    private fun testClient(status: Int, requests: MutableList<String>) = OkHttpClient.Builder()
        .addInterceptor { chain ->
            val request = chain.request()
            requests += request.url.host
            okhttp3.Response.Builder().request(request).protocol(okhttp3.Protocol.HTTP_1_1)
                .code(if (request.url.host == "primary.test") status else 204)
                .message("test").body(okhttp3.ResponseBody.create(null, ByteArray(0))).build()
        }.build()

    @Test fun `unavailable primary is confirmed with another endpoint`() = runBlocking {
        val requests = mutableListOf<String>()
        val result = ConnectivityProbe(testClient(503, requests))
            .checkAny(listOf("https://primary.test/", "https://fallback.test/"))
        assertTrue(result.healthy)
        assertEquals("fallback.test", result.reachedHost)
        assertEquals(listOf("primary.test", "fallback.test"), requests)
        assertEquals(listOf("primary.test: HTTP 503"), result.failures)
    }

    @Test fun `working primary does not send extra background requests`() = runBlocking {
        val requests = mutableListOf<String>()
        assertTrue(ConnectivityProbe(testClient(204, requests))
            .checkAny(listOf("https://primary.test/", "https://fallback.test/")).healthy)
        assertEquals(listOf("primary.test"), requests)
    }

    @Test fun `failed confirmation reports unhealthy and deduplicates URLs`() = runBlocking {
        val requests = mutableListOf<String>()
        val result = ConnectivityProbe(testClient(503, requests))
            .checkAny(listOf("https://primary.test/", "https://primary.test/"))
        assertFalse(result.healthy)
        assertNull(result.reachedHost)
        assertEquals(1, requests.size)
    }

    @Test fun `probe returns HTTP status without connection observations`() = runBlocking {
        ServerSocket(0).use { server ->
            val worker = thread(isDaemon = true) {
                server.accept().use { socket ->
                    val reader = socket.getInputStream().bufferedReader()
                    while (!reader.readLine().isNullOrEmpty()) { }
                    socket.getOutputStream().write("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
                }
            }
            assertEquals(204, ConnectivityProbe().check("http://127.0.0.1:${server.localPort}/"))
            worker.join(2_000)
        }
    }

    @Test fun `deadline includes stuck DNS before TCP starts`() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val client = OkHttpClient.Builder().dns(object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
            entered.countDown()
            release.await(5, TimeUnit.SECONDS)
            return listOf(InetAddress.getLoopbackAddress())
            }
        }).build()
        try {
            val result = async {
                try { ConnectivityProbe(client, 500).check("http://stalled.invalid/"); false }
                catch (_: TimeoutCancellationException) { true }
            }
            assertTrue(withContext(Dispatchers.IO) { entered.await(2, TimeUnit.SECONDS) })
            assertTrue(withTimeout(2_000) { result.await() })
            // DNS is deliberately still blocked, proving the caller deadline does not wait for it.
            assertEquals(1L, release.count)
        } finally {
            release.countDown()
            client.dispatcher.executorService.shutdownNow()
            client.connectionPool.evictAll()
        }
    }

    @Test fun `service cancellation does not wait for a stuck DNS worker`() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val client = OkHttpClient.Builder().dns(object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
            entered.countDown(); release.await(5, TimeUnit.SECONDS)
            return listOf(InetAddress.getLoopbackAddress())
            }
        }).build()
        try {
            val job = launch { ConnectivityProbe(client).check("http://stalled.invalid/") }
            assertTrue(withContext(Dispatchers.IO) { entered.await(2, TimeUnit.SECONDS) })
            withTimeout(1_000) { job.cancelAndJoin() }
            assertTrue(job.isCancelled)
            assertEquals(1L, release.count)
        } finally {
            release.countDown()
            client.dispatcher.executorService.shutdownNow()
            client.connectionPool.evictAll()
        }
    }

    @Test fun `parent timeout cancels confirmation instead of starting fallback`() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val lookups = java.util.concurrent.atomic.AtomicInteger()
        val client = OkHttpClient.Builder().dns(object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                lookups.incrementAndGet()
                entered.countDown()
                release.await(5, TimeUnit.SECONDS)
                return listOf(InetAddress.getLoopbackAddress())
            }
        }).build()
        try {
            val result = async {
                withTimeoutOrNull(500) {
                    ConnectivityProbe(client).checkAny(listOf("http://stalled.invalid/", "http://fallback.invalid/"))
                }
            }
            assertTrue(withContext(Dispatchers.IO) { entered.await(2, TimeUnit.SECONDS) })
            assertNull(withTimeout(2_000) { result.await() })
            assertEquals(1, lookups.get())
        } finally {
            release.countDown()
            client.dispatcher.executorService.shutdownNow()
            client.connectionPool.evictAll()
        }
    }
}
