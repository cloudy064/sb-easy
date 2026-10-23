package io.sbeasy.android.core

import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import okhttp3.Credentials
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

class NativeHttpDebugRoutingTest {
    @Test fun coreRejectsUnauthenticatedReturnLegAndForwardsAuthenticatedRequestsWithoutRecursion() {
        val executable = System.getenv("SB_EASY_SINGBOX")
        assumeTrue("Set SB_EASY_SINGBOX for native proxy authentication checks", !executable.isNullOrBlank())
        val folder = Files.createTempDirectory("sb-httpdebug-routing-").toFile()
        val secret = "b".repeat(64)
        val port = ServerSocket(0).use { it.localPort }
        MockWebServer().use { origin ->
            origin.enqueue(MockResponse().setBody("authenticated-return-leg"))
            origin.start()
            val base = """{"inbounds":[{"type":"tun","tag":"vpn","address":["172.19.0.1/30"]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""
            val runtime = JSONObject(HttpDebugRouting.apply(base, listOf("example.com"), secret))
            val upstream = runtime.getJSONArray("inbounds").getJSONObject(1).put("listen_port", port)
            runtime.put("inbounds", JSONArray().put(upstream)) // No TUN or privileged operation in this fixture.
            val config = folder.resolve("config.json").apply { writeText(runtime.toString()) }
            val log = folder.resolve("core.log")
            val process = ProcessBuilder(executable!!, "run", "-c", config.path).directory(folder).redirectErrorStream(true).redirectOutput(log).start()
            try {
                val client = OkHttpClient.Builder().proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port)))
                    .callTimeout(1, TimeUnit.SECONDS).build()
                val url = origin.url("/fixture").newBuilder().host("127.0.0.1").build()
                var ready = false
                for (attempt in 0 until 150) {
                    assertTrue("Native core exited: ${log.readText().takeLast(1500)}", process.isAlive)
                    ready = runCatching { client.newCall(Request.Builder().url(url).build()).execute().use { it.code == 407 } }.getOrDefault(false)
                    if (ready) break
                    Thread.sleep(100)
                }
                assertTrue("Native proxy did not demand authentication", ready)
                assertEquals(0, origin.requestCount)
                val authenticated = client.newBuilder().proxyAuthenticator { _, response ->
                    if (response.request.header("Proxy-Authorization") != null) null
                    else response.request.newBuilder().header("Proxy-Authorization", Credentials.basic("sbeasy", secret)).build()
                }.build()
                authenticated.newCall(Request.Builder().url(url).build()).execute().use { response ->
                    assertEquals(200, response.code)
                    assertEquals("authenticated-return-leg", response.body!!.string())
                }
                assertEquals(1, origin.requestCount)
                assertNull("Return-leg credentials leaked to origin", origin.takeRequest().getHeader("Proxy-Authorization"))
            } finally {
                process.destroy()
                if (!process.waitFor(3, TimeUnit.SECONDS)) { process.destroyForcibly(); process.waitFor(3, TimeUnit.SECONDS) }
                folder.deleteRecursively()
            }
        }
    }
}
