package io.sbeasy.android.core

import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Optional native test starts only an isolated loopback core and two local mock servers; no TUN or public traffic. */
class NativeHealthApiTest {
    @Test fun realCoreAuthenticatesTestsDeadlineAndChangesOnlyRequestedSelector() = runBlocking {
        val executable = System.getenv("SB_EASY_SINGBOX")
        assumeTrue("Set SB_EASY_SINGBOX to exercise the actual sing-box API", !executable.isNullOrBlank())
        val directory = Files.createTempDirectory("sb-easy-health-native-").toFile()
        val certificate = HeldCertificate.Builder().commonName("localhost").addSubjectAlternativeName("127.0.0.1").addSubjectAlternativeName("localhost").build()
        val serverCertificates = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        MockWebServer().use { https -> ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { stalled ->
            https.useHttps(serverCertificates.sslSocketFactory(), false)
            https.enqueue(MockResponse().setResponseCode(204).setHeadersDelay(25, TimeUnit.MILLISECONDS))
            https.start()
            val requestSeen = CountDownLatch(1)
            val connectionClosed = CountDownLatch(1)
            val stalledPeer = Thread {
                runCatching { stalled.accept().use { socket ->
                    val input = socket.getInputStream()
                    val request = StringBuilder()
                    while (!request.endsWith("\r\n\r\n") && request.length < 32768) {
                        val next = input.read()
                        if (next < 0) return@use
                        request.append(next.toChar())
                    }
                    requestSeen.countDown()
                    if (input.read() == -1) connectionClosed.countDown()
                } }
            }.apply { isDaemon = true; start() }
            val api = LoopbackHealthApi.create()
            val base = JSONObject().put("log", JSONObject().put("level", "error"))
                .put("certificate", JSONObject().put("certificate", JSONArray(listOf(certificate.certificatePem()))))
                .put("outbounds", JSONArray()
                    .put(JSONObject().put("type", "http").put("tag", "failed").put("server", "127.0.0.1").put("server_port", stalled.localPort))
                    .put(JSONObject().put("type", "direct").put("tag", "working"))
                    .put(JSONObject().put("type", "selector").put("tag", "automatic").put("outbounds", JSONArray(listOf("failed", "working"))).put("default", "failed"))
                    .put(JSONObject().put("type", "selector").put("tag", "fixed").put("outbounds", JSONArray(listOf("failed", "working"))).put("default", "failed")))
                .put("route", JSONObject().put("final", "automatic"))
            val config = api.runtimeConfig(base.toString())
            val configFile = directory.resolve("runtime.json").apply { writeText(config) }
            val logs = directory.resolve("core.log")
            val trustFile = directory.resolve("trust.pem").apply { writeText(certificate.certificatePem()) }
            val process = ProcessBuilder(executable!!, "run", "-c", configFile.path).directory(directory).redirectErrorStream(true).redirectOutput(logs)
                .apply { environment()["SSL_CERT_FILE"] = trustFile.path }.start()
            try {
                val client = OkHttpClient.Builder().callTimeout(1, TimeUnit.SECONDS).build()
                val origin = "http://127.0.0.1:${api.port}"
                var ready = false
                for (attempt in 0 until 60) {
                    assertTrue("Native core exited: ${logs.readText().takeLast(2000)}", process.isAlive)
                    ready = runCatching { client.newCall(Request.Builder().url(origin).build()).execute().use { it.code == 401 } }.getOrDefault(false)
                    if (ready) break
                    Thread.sleep(50)
                }
                assertTrue("Native controller never became ready", ready)
                val url = https.url("/health").toString()
                val started = System.nanoTime()
                val failure = api.probe("failed", url, 500)
                val elapsed = (System.nanoTime() - started) / 1_000_000
                assertFalse(failure.healthy)
                assertTrue("Probe exceeded requested deadline: $elapsed ms", elapsed < 2000)
                assertTrue(requestSeen.await(1, TimeUnit.SECONDS))
                assertTrue("Core retained the stalled CONNECT socket after its deadline", connectionClosed.await(2, TimeUnit.SECONDS))
                val healthy = api.probe("working", url, 1000)
                assertTrue("Working node failed: ${healthy.error}; core: ${logs.readText().takeLast(1500)}", healthy.healthy)
                assertEquals("HEAD", https.takeRequest(1, TimeUnit.SECONDS)!!.method)
                assertEquals("working", HealthSelection.choose("failed", listOf("failed", "working"), listOf(failure, healthy), HealthPolicy(timeoutMillis = 1000)))
                val secret = JSONObject(config).getJSONObject("experimental").getJSONObject("clash_api").getString("secret")
                fun request(path: String) = Request.Builder().url(origin + path).header("Authorization", "Bearer $secret")
                client.newCall(request("/proxies/automatic").put("{\"name\":\"working\"}".toRequestBody("application/json".toMediaType())).build()).execute().use {
                    assertEquals(204, it.code)
                }
                for ((tag, expected) in listOf("automatic" to "working", "fixed" to "failed")) {
                    client.newCall(request("/proxies/$tag").build()).execute().use { response ->
                        assertEquals(expected, JSONObject(response.body!!.string()).getString("now"))
                    }
                }
            } finally {
                process.destroy()
                if (!process.waitFor(3, TimeUnit.SECONDS)) { process.destroyForcibly(); process.waitFor(3, TimeUnit.SECONDS) }
                stalledPeer.join(1000)
                directory.deleteRecursively()
            }
        } }
    }
}
