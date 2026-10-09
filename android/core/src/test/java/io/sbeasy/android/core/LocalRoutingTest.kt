package io.sbeasy.android.core

import java.io.File
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalRoutingTest {
    private val base = """
        {
          "log":{"level":"debug"},
          "dns": {
            "servers":[{"type":"https","tag":"bootstrap-dns","server":"223.5.5.5","detour":"direct"}],
            "rules":[],"final":"bootstrap-dns"
          },
          "outbounds":[
            {"type":"socks","tag":"Tokyo","server":"127.0.0.1","server_port":31001},
            {"type":"socks","tag":"US","server":"127.0.0.1","server_port":31002},
            {"type":"socks","tag":"Singapore","server":"127.0.0.1","server_port":31003},
            {"type":"direct","tag":"direct"},
            {"type":"urltest","tag":"auto","outbounds":["Tokyo","US","Singapore"],"interval":"24h","idle_timeout":"24h"},
            {"type":"selector","tag":"Proxy","outbounds":["auto","Tokyo","US","Singapore","direct"],"default":"auto"}
          ],
          "route": {
            "rules":[
              {"ip_cidr":["192.0.2.1/32"],"outbound":"direct"},
              {"action":"sniff"},
              {"protocol":"dns","action":"hijack-dns"},
              {"domain_suffix":["anthropic.com","claude.ai"],"outbound":"Tokyo"},
              {"domain_suffix":["blocked.example.com"],"action":"reject"},
              {"rule_set":["geosite-cn"],"outbound":"direct"}
            ],
            "rule_set":[
              {"type":"inline","tag":"geosite-private","rules":[{"domain_suffix":["lan","local"]}]},
              {"type":"inline","tag":"geosite-cn","rules":[{"domain_suffix":["qq.com","baidu.com"]}]},
              {"type":"inline","tag":"geoip-cn","rules":[{"ip_cidr":["223.5.5.0/24"]}]}
            ],
            "final":"Proxy"
          },
          "experimental":{"cache_file":{"enabled":true,"cache_id":"managed"}}
        }
    """.trimIndent()

    private fun independentPolicy(): LocalRoutingPolicy = LocalRouting.defaults(base).let { policy ->
        policy.copy(defaultOutbound = "Singapore", groups = policy.groups.map {
            it.copy(outbound = if (it.id == "claude") "Tokyo" else "US")
        } + LocalRoutingGroup("custom", "工作", listOf("work.example.org"), "US"))
    }

    @Test fun androidTunUsesUserspaceTcpWithoutChangingRoutingChoicesOrSource() {
        val source = JSONObject(base).put("inbounds", JSONArray().put(JSONObject()
            .put("type", "tun").put("tag", "tun-in").put("stack", "mixed")
            .put("address", JSONArray(listOf("172.19.0.1/30"))).put("mtu", 9000))
            .put(JSONObject().put("type", "mixed").put("tag", "local-proxy").put("listen_port", 2080)))
        val before = source.toString()
        val policy = independentPolicy()
        val rendered = LocalRouting.render(before, policy).content
        val inbounds = JSONObject(rendered).getJSONArray("inbounds")
        assertEquals("gvisor", inbounds.getJSONObject(0).getString("stack"))
        assertEquals("172.19.0.1/30", inbounds.getJSONObject(0).getJSONArray("address").getString(0))
        assertEquals(9000, inbounds.getJSONObject(0).getInt("mtu"))
        assertFalse(inbounds.getJSONObject(1).has("stack"))
        assertEquals(before, source.toString())
        assertEquals(LocalRouting.selectionsFromConfig(LocalRouting.render(base, policy).content),
            LocalRouting.selectionsFromConfig(rendered))
    }

    @Test fun defaultsReuseTheProvisionedFixedClaudeNode() {
        val policy = LocalRouting.defaults(base)
        assertEquals("Tokyo", policy.defaultOutbound)
        assertEquals(listOf("Claude", "GPT"), policy.groups.map { it.name })
        assertTrue(policy.groups.all { it.outbound == "Tokyo" })
        assertEquals(listOf("Tokyo", "US", "Singapore"), LocalRouting.availableNodes(base).map { it.tag })
    }

    private fun provisionedBase(): String = JSONObject(base).also { root ->
        val route = root.getJSONObject("route")
        route.put("final", "Singapore")
        objects(route.getJSONArray("rules")).single { it.optJSONArray("domain_suffix")?.toString()?.contains("anthropic.com") == true }
            .put("outbound", "US")
        route.getJSONArray("rules").put(JSONObject().put("domain_suffix", JSONArray(listOf("openai.com", "chatgpt.com")))
            .put("outbound", "Tokyo"))
    }.toString()

    @Test fun defaultsUseSeparateCentrallyProvisionedExits() {
        val policy = LocalRouting.defaults(provisionedBase())
        assertEquals("Singapore", policy.defaultOutbound)
        assertEquals("US", policy.groups.single { it.id == "claude" }.outbound)
        assertEquals("Tokyo", policy.groups.single { it.id == "gpt" }.outbound)
        assertEquals(1, policy.presetRevision)
    }

    @Test fun upgradeMigratesExistingPolicyOnceAndPreservesEditedGroups() {
        val legacy = JSONObject(LocalRouting.encode(independentPolicy())).also { it.remove("preset_revision") }.toString()
        val previous = LocalRouting.decode(legacy).let { p -> p.copy(groups = p.groups.map {
            if (it.id == "claude") it.copy(name = "Claude 工作", domains = it.domains + "gateway.example.net", includeOfficialApp = false) else it
        }) }
        val migrated = LocalRouting.migrateProvisionedDefaults(provisionedBase(), previous)
        assertEquals("Singapore", migrated.defaultOutbound)
        assertEquals("US", migrated.groups.single { it.id == "claude" }.outbound)
        assertEquals("Tokyo", migrated.groups.single { it.id == "gpt" }.outbound)
        assertEquals(previous.groups.single { it.id == "custom" }, migrated.groups.single { it.id == "custom" })
        assertEquals(previous.groups.single { it.id == "claude" }.copy(outbound = "US"), migrated.groups.single { it.id == "claude" })
        val edited = migrated.copy(defaultOutbound = "direct", groups = migrated.groups.map { it.copy(outbound = "Singapore") })
        val persisted = LocalRouting.decode(LocalRouting.encode(edited))
        assertEquals(edited, LocalRouting.migrateProvisionedDefaults(provisionedBase(), persisted))
    }

    @Test fun partialServerPresetsDoNotMigrateAndDeletedBuiltInGroupsStayDeleted() {
        val previous = independentPolicy()
        assertEquals(previous, LocalRouting.migrateProvisionedDefaults(base, previous))
        val deleted = previous.copy(groups = previous.groups.filter { it.id == "custom" })
        assertEquals(deleted.groups, LocalRouting.migrateProvisionedDefaults(provisionedBase(), deleted).groups)
    }

    @Test fun groupsHaveIndependentFixedExitsAndDefaultWithDnsFollowingEachGroup() {
        val result = LocalRouting.render(base, independentPolicy(), "https://manage.example.com:51821")
        val root = JSONObject(result.content)
        val outbounds = objects(root.getJSONArray("outbounds"))
        val route = root.getJSONObject("route")
        val rules = objects(route.getJSONArray("rules"))
        val dns = root.getJSONObject("dns")
        val servers = objects(dns.getJSONArray("servers"))
        val dnsRules = objects(dns.getJSONArray("rules"))
        val snapshot = result.snapshot
        assertEquals("Singapore", snapshot.selections[snapshot.defaultTag])
        assertEquals("Tokyo", snapshot.selections[snapshot.groupTags["claude"]])
        assertEquals("US", snapshot.selections[snapshot.groupTags["gpt"]])
        assertEquals(snapshot.defaultTag, route.getString("final"))
        snapshot.selections.forEach { (tag, selection) ->
            val selector = outbounds.single { it.optString("tag") == tag }
            assertEquals("selector", selector.getString("type"))
            assertEquals(selection, selector.getString("default"))
            assertEquals(listOf("Tokyo", "US", "Singapore", "direct"), strings(selector.getJSONArray("outbounds")))
            assertTrue(selector.getBoolean("interrupt_exist_connections"))
            val server = servers.single { it.optString("detour") == tag }
            assertEquals("https", server.getString("type"))
            if (tag == snapshot.defaultTag) assertEquals(server.getString("tag"), dns.getString("final"))
        }
        independentPolicy().groups.forEach { group ->
            val tag = snapshot.groupTags.getValue(group.id)
            val rule = rules.single { it.optString("outbound") == tag && it.has("domain_suffix") }
            assertEquals(group.domains, strings(rule.getJSONArray("domain_suffix")))
            val dnsRule = dnsRules.single { it.optJSONArray("domain_suffix")?.toString() == rule.getJSONArray("domain_suffix").toString() }
            assertEquals(tag, servers.single { it.optString("tag") == dnsRule.getString("server") }.getString("detour"))
        }
        val directDns = servers.single { it.getString("tag") == route.getJSONObject("default_domain_resolver").getString("server") }
        assertFalse(directDns.has("detour"))
        assertFalse(servers.single { it.optString("tag") == "bootstrap-dns" }.has("detour"))
        assertTrue(dns.getBoolean("reverse_mapping"))
        assertTrue(rules.indexOfFirst { it.optString("action") == "hijack-dns" } < rules.indexOfFirst { it.optString("outbound") == snapshot.groupTags["claude"] })
        assertTrue(rules.indexOfFirst { it.optString("outbound") == snapshot.groupTags["claude"] } < rules.indexOfFirst { it.has("rule_set") })
        assertFalse(rules.any { it.optString("outbound") == "Tokyo" })
        assertTrue(rules.any { it.optString("action") == "reject" })
        assertTrue(rules.any { it.optBoolean("ip_is_private") && it.optString("outbound") == "direct" })
        assertEquals("manage.example.com", rules.single { it.has("domain") }.getJSONArray("domain").getString(0))
    }

    @Test fun proxiedDnsKeepsAReachableHostnameForHttpConnectExits() {
        val source = JSONObject(base).also { root ->
            objects(root.getJSONArray("outbounds")).single { it.getString("tag") == "Tokyo" }.put("type", "http")
        }.toString()
        val rendered = LocalRouting.render(source, independentPolicy())
        val root = JSONObject(rendered.content)
        val dnsServers = objects(root.getJSONObject("dns").getJSONArray("servers"))
        rendered.snapshot.selections.keys.forEach { tag ->
            val server = dnsServers.single { it.optString("detour") == tag }
            assertEquals("dns.google", server.getString("server"))
            assertEquals("dns.google", server.getJSONObject("tls").getString("server_name"))
            assertFalse(server.has("domain_resolver"))
        }
        val direct = dnsServers.single {
            it.getString("tag") == root.getJSONObject("route").getJSONObject("default_domain_resolver").getString("server")
        }
        assertEquals("223.5.5.5", direct.getString("server"))
        assertFalse(direct.has("detour"))
    }

    @Test fun httpExitsMapBrowserIpsBackToNamesAndKeepDnsTransitionsConsistent() {
        val source = JSONObject(base).also { root ->
            objects(root.getJSONArray("outbounds")).filter { it.optString("tag") in listOf("Tokyo", "US") }
                .forEach { it.put("type", "http") }
        }.toString()
        val policy = independentPolicy()
        val result = LocalRouting.render(source, policy)
        val root = JSONObject(result.content)
        val dns = root.getJSONObject("dns")
        val servers = objects(dns.getJSONArray("servers"))
        val rules = objects(dns.getJSONArray("rules"))
        val fake = servers.single { it.getString("type") == "fakeip" }
        assertEquals("198.18.0.0/15", fake.getString("inet4_range"))
        assertTrue(root.getJSONObject("experimental").getJSONObject("cache_file").getBoolean("store_fakeip"))
        assertEquals("managed", root.getJSONObject("experimental").getJSONObject("cache_file").getString("cache_id"))
        policy.groups.forEach { group ->
            val domainRules = rules.filter { it.optJSONArray("domain_suffix")?.toString() == JSONArray(group.domains).toString() }
            assertEquals(listOf("HTTPS", "SVCB"), strings(domainRules[0].getJSONArray("query_type")))
            assertEquals("predefined", domainRules[0].getString("action"))
            assertEquals("NOERROR", domainRules[0].getString("rcode"))
            assertEquals(listOf("A", "AAAA"), strings(domainRules[1].getJSONArray("query_type")))
            assertEquals(fake.getString("tag"), domainRules[1].getString("server"))
        }
        val switchedHttp = policy.copy(groups = policy.groups.map { it.copy(outbound = "US") })
        assertTrue(LocalRouting.sameDnsConfiguration(result.content, LocalRouting.render(source, switchedHttp).content))
        val switchedSocks = policy.copy(groups = policy.groups.map { it.copy(outbound = "Singapore") })
        assertFalse(LocalRouting.sameDnsConfiguration(result.content, LocalRouting.render(source, switchedSocks).content))
        val direct = policy.copy(defaultOutbound = "direct", groups = policy.groups.map { it.copy(outbound = "direct") })
        val directResult = LocalRouting.render(source, direct)
        val directDns = JSONObject(directResult.content).getJSONObject("dns")
        assertEquals(1, objects(directDns.getJSONArray("servers")).count { it.optString("type") == "fakeip" })
        assertFalse(objects(directDns.getJSONArray("rules")).any { it.has("query_type") })
        assertTrue(objects(directDns.getJSONArray("rules")).filter { it.has("domain_suffix") }
            .all { it.getString("server") == directDns.getString("final") })
        assertFalse(LocalRouting.sameDnsConfiguration(result.content, directResult.content))
        val defaultHttp = LocalRouting.render(source, policy.copy(defaultOutbound = "Tokyo"))
        val defaultRules = objects(JSONObject(defaultHttp.content).getJSONObject("dns").getJSONArray("rules"))
        assertTrue(defaultRules.indexOfFirst { it.has("rule_set") } <
            defaultRules.indexOfFirst { it.has("query_type") && !it.has("domain_suffix") && !it.has("package_name") })
    }

    @Test fun ipv4OnlyAndroidTunDoesNotAdvertiseUnroutableFakeIpv6() {
        val source = JSONObject(base).also { root ->
            root.put("inbounds", JSONArray().put(JSONObject().put("type", "tun").put("address", JSONArray(listOf("172.19.0.1/30")))))
            objects(root.getJSONArray("outbounds")).single { it.getString("tag") == "Tokyo" }.put("type", "http")
        }
        fun fakeRules(content: String): List<JSONObject> {
            val dns = JSONObject(LocalRouting.render(content, independentPolicy()).content).getJSONObject("dns")
            val tag = objects(dns.getJSONArray("servers")).single { it.getString("type") == "fakeip" }.getString("tag")
            return objects(dns.getJSONArray("rules")).filter { it.optString("server") == tag }
        }
        assertTrue(fakeRules(source.toString()).isNotEmpty())
        assertTrue(fakeRules(source.toString()).all { it.getString("strategy") == "ipv4_only" })
        source.getJSONArray("inbounds").getJSONObject(0).getJSONArray("address").put("fdfe:dcba:9876::1/126")
        assertTrue(fakeRules(source.toString()).all { !it.has("strategy") })
    }

    @Test fun officialAppTrafficUsesItsGroupEvenForUnlistedDomainsAndCanBeDisabled() {
        val policy = independentPolicy()
        val rendered = LocalRouting.render(base, policy)
        val rules = objects(JSONObject(rendered.content).getJSONObject("route").getJSONArray("rules"))
        val claudeRule = rules.single { it.optJSONArray("package_name")?.getString(0) == "com.anthropic.claude" }
        assertEquals(rendered.snapshot.groupTags["claude"], claudeRule.getString("outbound"))
        val gptRule = rules.single { it.optJSONArray("package_name")?.getString(0) == "com.openai.chatgpt" }
        assertEquals(rendered.snapshot.groupTags["gpt"], gptRule.getString("outbound"))
        assertTrue(rules.indexOf(gptRule) < rules.indexOfFirst { it.has("rule_set") })
        val disabled = LocalRouting.render(base, policy.copy(groups = policy.groups.map { it.copy(includeOfficialApp = false) }))
        assertFalse(objects(JSONObject(disabled.content).getJSONObject("route").getJSONArray("rules")).any { it.has("package_name") })
    }

    @Test fun restartAndServerSyncRetainUserChoicesAndEditedDomains() {
        val policy = independentPolicy().let { p -> p.copy(groups = p.groups.map {
            if (it.id == "claude") it.copy(domains = it.domains + "my-claude-gateway.example.net", outbound = "US") else it
        }) }
        val stored = LocalRouting.decode(LocalRouting.encode(policy))
        val refreshed = JSONObject(base).also {
            it.getJSONArray("outbounds").put(JSONObject().put("type", "socks").put("tag", "New node")
                .put("server", "127.0.0.1").put("server_port", 31004))
        }.toString()
        val result = LocalRouting.render(refreshed, stored)
        assertEquals(policy, result.snapshot.policy)
        assertEquals("US", result.snapshot.selections[result.snapshot.groupTags["claude"]])
        assertEquals("Singapore", result.snapshot.selections[result.snapshot.defaultTag])
        assertTrue(result.snapshot.availableNodes.any { it.tag == "New node" })
        assertEquals(LocalRouting.render(base, policy).content, LocalRouting.render(base, stored).content)
        assertEquals(6, JSONObject(base).getJSONArray("outbounds").length())
        assertEquals("Proxy", JSONObject(base).getJSONObject("route").getString("final"))
    }

    @Test fun removedNodesHaveAVisibleConcreteFallbackWithoutChangingSavedChoice() {
        val policy = independentPolicy()
        val root = JSONObject(base)
        val updated = JSONArray()
        objects(root.getJSONArray("outbounds")).filterNot { it.optString("tag") == "Tokyo" }.forEach(updated::put)
        root.put("outbounds", updated)
        val result = LocalRouting.render(root.toString(), policy)
        assertEquals("Tokyo", result.snapshot.policy!!.groups.single { it.id == "claude" }.outbound)
        assertEquals("US", result.snapshot.selections[result.snapshot.groupTags["claude"]])
        assertTrue(result.snapshot.warnings.single().contains("Tokyo"))
        assertFalse(result.snapshot.selections.values.any { it == "auto" || it == "Proxy" })
    }

    @Test fun deletionRemovesGroupRoutesAndSelectingDirectIsSupported() {
        val policy = independentPolicy().copy(defaultOutbound = "direct", groups = emptyList())
        val result = LocalRouting.render(base, policy)
        assertTrue(result.snapshot.groupTags.isEmpty())
        assertEquals("direct", result.snapshot.selections[result.snapshot.defaultTag])
        assertFalse(objects(JSONObject(result.content).getJSONObject("route").getJSONArray("rules"))
            .any { it.optJSONArray("domain_suffix")?.toString()?.contains("anthropic.com") == true })
    }

    @Test fun generatedTagsAvoidCollisionsAndManagementEndpointRoutesArePreserved() {
        val root = JSONObject(base)
        root.getJSONArray("outbounds").put(JSONObject().put("type", "socks").put("tag", "sb-easy-local-claude")
            .put("server", "127.0.0.1").put("server_port", 31004))
        root.put("endpoints", JSONArray().put(JSONObject().put("type", "wireguard").put("tag", "sb-easy-network")))
        root.getJSONObject("route").getJSONArray("rules").put(JSONObject().put("ip_cidr", JSONArray(listOf("10.59.32.0/24")))
            .put("outbound", "sb-easy-network"))
        val result = LocalRouting.render(root.toString(), independentPolicy())
        assertEquals("sb-easy-local-claude-local", result.snapshot.groupTags["claude"])
        val rules = objects(JSONObject(result.content).getJSONObject("route").getJSONArray("rules"))
        assertTrue(rules.indexOfFirst { it.optString("outbound") == "sb-easy-network" } < rules.indexOfFirst { it.optBoolean("ip_is_private") })
    }

    @Test fun selectionsAreRestoredFromSavedPolicyAndPreserveRuleSetCacheNamespace() {
        fun cacheId(content: String, policy: LocalRoutingPolicy) = JSONObject(LocalRouting.render(content, policy).content)
            .getJSONObject("experimental").getJSONObject("cache_file").getString("cache_id")
        val policy = independentPolicy()
        val original = cacheId(base, policy)
        assertEquals(original, cacheId(JSONObject(base).put("log", JSONObject().put("level", "warn")).toString(), policy))
        assertEquals("managed", original)
        assertEquals(original, cacheId(base, policy.copy(defaultOutbound = "Tokyo")))
        assertEquals(original, cacheId(base, policy.copy(groups = policy.groups.map { it.copy(outbound = "Singapore") })))
        val rendered = LocalRouting.render(base, policy)
        assertEquals(rendered.snapshot.selections, LocalRouting.selectionsFromConfig(rendered.content))
    }

    @Test fun normalizesDomainListsAndRejectsInvalidOrAmbiguousGroups() {
        assertEquals(listOf("example.com", "xn--fiqs8s.example"), LocalRouting.normalizeDomains("*.EXAMPLE.com, .example.com.\n中国.example"))
        listOf("https://example.com/a", "example.com:443", "127.0.0.1", "-bad.example", "foo.*.example", "localhost", "").forEach { invalid ->
            assertTrue(invalid, runCatching { LocalRouting.normalizeDomains(invalid) }.isFailure)
        }
        val defaults = LocalRouting.defaults(base)
        assertTrue(runCatching { LocalRouting.validate(defaults.copy(groups = defaults.groups +
            LocalRoutingGroup("another", "另一个", listOf("api.anthropic.com"), "US"))) }.isFailure)
        assertTrue(runCatching { LocalRouting.validate(defaults.copy(groups = defaults.groups +
            LocalRoutingGroup("another", "Claude", listOf("another.example.net"), "US"))) }.isFailure)
    }

    @Test fun writesOptionalNativePreflightFixtures() {
        val folder = System.getenv("SB_EASY_ROUTING_FIXTURE_DIR")?.let(::File) ?: return
        folder.mkdirs()
        File(folder, "routing.json").writeText(LocalRouting.render(base, independentPolicy(), "http://manage.example.com:51821").content)
        val httpBase = JSONObject(base).also { root ->
            objects(root.getJSONArray("outbounds")).filter { it.optString("tag") in listOf("Tokyo", "US", "Singapore") }
                .forEach { it.put("type", "http") }
        }.toString()
        File(folder, "routing-http.json").writeText(LocalRouting.render(httpBase, independentPolicy(), "http://manage.example.com:51821").content)
        val ipv4Http = JSONObject(httpBase).put("inbounds", JSONArray().put(JSONObject().put("type", "tun")
            .put("address", JSONArray(listOf("172.19.0.1/30"))).put("auto_route", true)))
        File(folder, "routing-http-ipv4.json").writeText(LocalRouting.render(ipv4Http.toString(), independentPolicy(),
            "http://manage.example.com:51821").content)
        File(folder, "routing-direct.json").writeText(LocalRouting.render(httpBase, independentPolicy().let { p ->
            p.copy(defaultOutbound = "direct", groups = p.groups.map { it.copy(outbound = "direct") })
        }, "http://manage.example.com:51821").content)
        val saved = independentPolicy().let { policy -> policy.copy(groups = policy.groups.map {
            if (it.id == "claude") it.copy(outbound = "US") else it
        }) }
        File(folder, "routing-claude-us.json").writeText(LocalRouting.render(base, saved, "http://manage.example.com:51821").content)
        System.getenv("SB_EASY_ROUTING_PRODUCTION_CONFIG")?.let { path ->
            val content = File(path).readText()
            File(folder, "production-routing.json").writeText(LocalRouting.render(content, LocalRouting.defaults(content), "http://39.108.98.208:51821").content)
        }
    }

    private fun objects(array: JSONArray): List<JSONObject> = (0 until array.length()).map { array.getJSONObject(it) }
    private fun strings(array: JSONArray): List<String> = (0 until array.length()).map { array.getString(it) }
}
