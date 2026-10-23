package io.sbeasy.android.core

import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ProxyHealthTest {
    private val base = """{
      "inbounds":[{"type":"tun","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"auto_route":true}],
      "outbounds":[{"type":"socks","tag":"A","server":"127.0.0.1","server_port":31001},
                   {"type":"http","tag":"B","server":"127.0.0.1","server_port":31002}],
      "dns":{"servers":[{"type":"udp","tag":"bootstrap","server":"223.5.5.5"}]},"route":{}
    }""".trimIndent()
    private val failed = NodeHealthResult("A", null, "timeout")

    @Test fun fastestHonorsToleranceAndFailoverRetainsWorkingAddress() {
        val results = listOf(NodeHealthResult("A", 160), NodeHealthResult("B", 100), NodeHealthResult("unlisted", 1))
        assertEquals("A", HealthSelection.choose("A", listOf("A", "B"), results, HealthPolicy()))
        assertEquals("A", HealthSelection.choose("A", listOf("A", "B"), results, HealthPolicy(selection = AutomaticSelection.FASTEST, toleranceMillis = 60)))
        assertEquals("B", HealthSelection.choose("A", listOf("A", "B"), results, HealthPolicy(selection = AutomaticSelection.FASTEST, toleranceMillis = 59)))
        assertEquals("B", HealthSelection.choose("missing", listOf("A", "B"), results, HealthPolicy()))
    }

    @Test fun failedCandidatesNeverPermitDirectOrOutOfPoolFallback() {
        assertEquals("B", HealthSelection.choose("A", listOf("A", "B"), listOf(failed, NodeHealthResult("B", 100)), HealthPolicy()))
        assertNull(HealthSelection.choose("A", listOf("A"), listOf(failed, NodeHealthResult("direct", 1), NodeHealthResult("B", 2)), HealthPolicy()))
        assertNull(HealthSelection.choose("A", listOf("A"), listOf(NodeHealthResult("A", 6000)), HealthPolicy(timeoutMillis = 5000)))
    }

    @Test fun healthPolicyValidationRejectsUnsupportedAndCredentialBearingUrls() {
        for (url in listOf("http://example.com", "file:///etc/passwd", "https://user:pass@example.com", "https://example.com/#fragment")) {
            assertTrue(runCatching { HealthPolicy(probeUrl = url).validate() }.isFailure)
        }
        for (timeout in listOf(0, 499, 30001, 32768)) assertTrue(runCatching { HealthPolicy(timeoutMillis = timeout).validate() }.isFailure)
        for (interval in listOf(0, 29, 86401)) assertTrue(runCatching { HealthPolicy(intervalSeconds = interval).validate() }.isFailure)
        val policy = HealthPolicy(timeoutMillis = 30000, toleranceMillis = 0, selection = AutomaticSelection.FASTEST)
        assertEquals(policy, HealthPolicy.decode(policy.json()))
    }

    @Test fun automaticSelectorsUseExplicitCandidatePoolAndDnsHandlesHttpCandidate() {
        val original = LocalRouting.defaults(base).copy(defaultOutbound = LocalRouting.AUTOMATIC,
            defaultAutomaticCandidates = listOf("A", "B"), groups = emptyList())
        val policy = LocalRouting.decode(LocalRouting.encode(original))
        assertEquals(original, policy)
        val rendered = LocalRouting.render(base, policy, includeGeoRules = false)
        val root = JSONObject(rendered.content)
        val selector = objects(root.getJSONArray("outbounds")).single { it.optString("tag") == rendered.snapshot.defaultTag }
        assertEquals(listOf("A", "B"), strings(selector.getJSONArray("outbounds")))
        assertEquals("A", selector.getString("default"))
        assertFalse(selector.has("timeout"))
        assertEquals(listOf("A", "B"), rendered.snapshot.automaticGroups[rendered.snapshot.defaultTag])
        assertTrue(objects(root.getJSONObject("dns").getJSONArray("rules")).any { it.optJSONArray("query_type")?.toString()?.contains("AAAA") == true })
        assertTrue(objects(root.getJSONObject("dns").getJSONArray("servers")).any { it.optString("detour") == rendered.snapshot.defaultTag })
        System.getenv("SB_EASY_ROUTING_FIXTURE_DIR")?.let { folder -> File(folder).mkdirs(); File(folder, "automatic.json").writeText(rendered.content) }
    }

    @Test fun emptyAutomaticPoolAndMissingFixedNodeBlockDataAndDns() {
        for (policy in listOf(
            LocalRoutingPolicy("removed", emptyList()),
            LocalRoutingPolicy(LocalRouting.AUTOMATIC, emptyList(), defaultAutomaticCandidates = listOf("removed")),
        )) {
            val rendered = LocalRouting.render(base, policy, includeGeoRules = false)
            assertTrue(rendered.snapshot.defaultTag in rendered.snapshot.blockedGroups)
            val root = JSONObject(rendered.content)
            val rules = objects(root.getJSONObject("route").getJSONArray("rules"))
            assertEquals("reject", rules.last().getString("action"))
            val dns = objects(root.getJSONObject("dns").getJSONArray("rules"))
            assertEquals("REFUSED", dns.last().getString("rcode"))
            System.getenv("SB_EASY_ROUTING_FIXTURE_DIR")?.let { folder -> File(folder).mkdirs(); File(folder, "blocked.json").writeText(rendered.content) }
        }
    }

    @Test fun candidatesMustBeExplicitBoundedAndExcludeDirect() {
        val defaults = LocalRouting.defaults(base)
        assertTrue(runCatching { LocalRouting.validate(defaults.copy(defaultOutbound = LocalRouting.AUTOMATIC)) }.isFailure)
        assertTrue(runCatching { LocalRouting.validate(defaults.copy(defaultAutomaticCandidates = listOf("direct"))) }.isFailure)
        assertTrue(runCatching { LocalRouting.validate(defaults.copy(defaultAutomaticCandidates = List(33) { "n$it" })) }.isFailure)
        assertTrue(runCatching { LocalRouting.validate(defaults.copy(defaultOutbound = LocalRouting.AUTOMATIC, defaultAutomaticCandidates = listOf("A"), health = HealthPolicy(enabled = false))) }.isFailure)
    }

    @Test fun runtimeApiOverridesRemoteControllerAndNeverChangesPersistedConfig() {
        val source = JSONObject(base).put("experimental", JSONObject().put("cache_file", JSONObject().put("enabled", true))
            .put("clash_api", JSONObject().put("external_controller", "0.0.0.0:9090").put("secret", "center-secret").put("external_ui", "dashboard"))).toString()
        val before = source
        val endpoint = LoopbackHealthApi(32123, "test-secret-012345678901234567890123")
        val applied = JSONObject(endpoint.runtimeConfig(source))
        val api = applied.getJSONObject("experimental").getJSONObject("clash_api")
        assertEquals("127.0.0.1:32123", api.getString("external_controller"))
        assertFalse(applied.toString().contains("center-secret"))
        assertFalse(api.has("external_ui"))
        assertTrue(applied.getJSONObject("experimental").getJSONObject("cache_file").getBoolean("enabled"))
        assertEquals(before, source)
    }

    @Test fun probeUsesRequestedUrlAndTimeoutAndEscapesOutboundTag() = runBlocking {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody("{\"delay\":81}"))
            server.start()
            val api = LoopbackHealthApi(server.port, "test-secret-012345678901234567890123")
            val result = api.probe("node / # 東京", "https://example.com/check?value=one&two=2", 1200)
            assertTrue(result.healthy)
            assertEquals(81, result.latencyMillis)
            val request = server.takeRequest()
            assertEquals("Bearer test-secret-012345678901234567890123", request.getHeader("Authorization"))
            assertEquals(listOf("proxies", "node / # 東京", "delay"), request.requestUrl!!.pathSegments)
            assertEquals("1200", request.requestUrl!!.queryParameter("timeout"))
            assertEquals("https://example.com/check?value=one&two=2", request.requestUrl!!.queryParameter("url"))
        }
    }

    @Test fun probeFailureDoesNotExposeUrlOrResponseAndCancellationStopsRequest() = runBlocking {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(503).setBody("secret-core-error"))
            server.enqueue(MockResponse().setBody("{\"delay\":1}").setBodyDelay(2, TimeUnit.SECONDS))
            server.start()
            val api = LoopbackHealthApi(server.port, "test-secret-012345678901234567890123")
            val failure = api.probe("A", "https://example.com/check?token=secret", 1000)
            assertFalse(failure.healthy)
            assertFalse(failure.error.orEmpty().contains("secret"))
            val pending = async { api.probe("A", "https://example.com/check", 1000) }
            delay(50)
            pending.cancel()
            runCatching { pending.await() }
            assertTrue(pending.isCancelled)
        }
    }

    private fun objects(array: JSONArray) = (0 until array.length()).map { array.getJSONObject(it) }
    private fun strings(array: JSONArray) = (0 until array.length()).map { array.getString(it) }
}
