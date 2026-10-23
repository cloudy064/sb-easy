package io.sbeasy.android.core

import java.net.IDN
import java.net.URI
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

data class LocalRoutingGroup(
    val id: String,
    val name: String,
    val domains: List<String>,
    val outbound: String,
    val includeOfficialApp: Boolean = true,
    val packages: List<String> = emptyList(),
    val automaticCandidates: List<String> = emptyList(),
)

data class LocalRoutingPolicy(
    val defaultOutbound: String,
    val groups: List<LocalRoutingGroup>,
    val presetRevision: Int = 0,
    val health: HealthPolicy = HealthPolicy(),
    val defaultAutomaticCandidates: List<String> = emptyList(),
)

data class LocalRoutingSnapshot(
    val policy: LocalRoutingPolicy? = null,
    val availableNodes: List<ProxyItemSnapshot> = emptyList(),
    val defaultTag: String = "",
    val groupTags: Map<String, String> = emptyMap(),
    val warnings: List<String> = emptyList(),
    val selections: Map<String, String> = emptyMap(),
    val automaticGroups: Map<String, List<String>> = emptyMap(),
    val blockedGroups: Set<String> = emptySet(),
)

data class LocalRoutingResult(
    val content: String,
    val snapshot: LocalRoutingSnapshot,
)

/** A device-owned overlay. Always render from the untouched server snapshot. */
object LocalRouting {
    const val TAG_PREFIX = "sb-easy-local-"
    const val AUTOMATIC = "@sb-easy-automatic"
    private val excludedTypes = setOf("selector", "urltest", "block", "dns", "direct")
    private val idPattern = Regex("[a-zA-Z0-9-]{1,64}")

    fun officialAppName(id: String): String? = when (id) {
        "claude" -> "Claude"
        "gpt" -> "ChatGPT"
        else -> null
    }

    private fun officialPackage(group: LocalRoutingGroup): String? = if (!group.includeOfficialApp) null else when (group.id) {
        "claude" -> "com.anthropic.claude"
        "gpt" -> "com.openai.chatgpt"
        else -> null
    }

    fun effectivePackages(group: LocalRoutingGroup): List<String> =
        (group.packages + listOfNotNull(officialPackage(group))).distinct()

    fun normalizePackages(input: String): List<String> = input.split(Regex("[\\s,，;；]+"))
        .filter(String::isNotBlank).distinct().also { packages ->
            require(packages.size <= 128) { "每组最多选择 128 个应用" }
            require(packages.all { it.length <= 255 && it.matches(Regex("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)+")) }) {
                "应用包名格式无效，例如 com.example.app"
            }
        }

    // Seeded from the MetaCubeX anthropic/openai domain lists, 2026-10-04.
    // Lists remain editable so additional APIs, gateways and login hosts can be added.
    private val claudeDomains = listOf(
        "anthropic.com", "clau.de", "claude.ai", "claude.com", "claude.dev",
        "claudemcpclient.com", "claudemcpcontent.com", "claudeusercontent.com",
        "servd-anthropic-website.b-cdn.net", "anyrouter.top",
    )
    private val gptDomains = listOf(
        "openai.com", "chatgpt.com", "chatgpt.site", "oaistatic.com", "oaistatsig.com",
        "oaiusercontent.com", "chat.com", "sora.com", "chatgpt.livekit.cloud",
        "host.livekit.cloud", "turn.livekit.cloud", "openai.com.cdn.cloudflare.net",
        "openaiapi-site.azureedge.net", "openaiassets.blob.core.windows.net",
        "openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net", "openaicom.imgix.net",
        "openaicomproductionae4b.blob.core.windows.net", "production-openaicom-storage.azureedge.net",
        "browser-intake-datadoghq.com", "o33249.ingest.sentry.io",
    )

    fun availableNodes(content: String): List<ProxyItemSnapshot> =
        objects(JSONObject(content).optJSONArray("outbounds"))
            .filter { it.optString("type") !in excludedTypes && it.optString("tag").isNotBlank() }
            .map { ProxyItemSnapshot(it.getString("tag"), it.optString("type"), 0, 0) }
            .distinctBy { it.tag }

    fun defaults(content: String): LocalRoutingPolicy {
        val root = JSONObject(content)
        val nodes = availableNodes(content).map { it.tag }
        val route = root.optJSONObject("route")
        fun fixed(domains: Set<String>): String? = objects(route?.optJSONArray("rules")).firstOrNull { rule ->
            strings(rule.optJSONArray("domain_suffix")).any { it.trimStart('.') in domains } &&
                rule.optString("outbound") in nodes
        }?.optString("outbound")
        val claude = fixed(setOf("anthropic.com", "claude.ai", "claude.com"))
        val gpt = fixed(setOf("openai.com", "chatgpt.com"))
        val final = route?.optString("final")?.takeIf { it in nodes }
        val selected = final ?: claude ?: nodes.firstOrNull() ?: "direct"
        return LocalRoutingPolicy(
            selected,
            listOf(
                LocalRoutingGroup("claude", "Claude", claudeDomains, claude ?: selected),
                LocalRoutingGroup("gpt", "GPT", gptDomains, gpt ?: selected),
            ),
            presetRevision = if (claude != null && gpt != null && final != null) 1 else 0,
        )
    }

    /** Apply the newly provisioned three-exit preset once; later syncs retain device choices. */
    fun migrateProvisionedDefaults(content: String, policy: LocalRoutingPolicy): LocalRoutingPolicy {
        if (policy.presetRevision >= 1) return policy
        val provisioned = defaults(content)
        if (provisioned.presetRevision == 0) return policy
        val exits = provisioned.groups.associate { it.id to it.outbound }
        return policy.copy(
            defaultOutbound = provisioned.defaultOutbound,
            groups = policy.groups.map { group -> exits[group.id]?.let { group.copy(outbound = it) } ?: group },
            presetRevision = provisioned.presetRevision,
        )
    }

    fun normalizeDomains(input: String): List<String> {
        val values = input.split(Regex("[\\s,，;；]+"))
            .filter { it.isNotBlank() }
            .map { raw ->
                val trimmed = raw.trim().removePrefix("*.").trimStart('.').trimEnd('.')
                require(!trimmed.contains(Regex("[/@:?#*]"))) { "请填写域名，例如 example.com，不要包含网址路径或端口" }
                val domain = runCatching { IDN.toASCII(trimmed).lowercase(Locale.ROOT) }
                    .getOrElse { throw IllegalArgumentException("无效域名：$raw") }
                require(domain.length <= 253 && domain.contains('.') && domain.split('.').all { label ->
                    label.isNotEmpty() && label.length <= 63 &&
                        label.first() != '-' && label.last() != '-' && label.all { it.isLetterOrDigit() || it == '-' }
                } && !domain.matches(Regex("[0-9.]+"))) { "无效域名：$raw" }
                domain
            }.distinct()
        require(values.isNotEmpty()) { "至少填写一个域名" }
        require(values.size <= 256) { "每组最多填写 256 个域名" }
        return values
    }

    fun validate(policy: LocalRoutingPolicy) {
        require(policy.defaultOutbound.isNotBlank()) { "请选择默认代理" }
        policy.health.validate()
        fun validateCandidates(selected: String, candidates: List<String>) {
            require(candidates.size <= 32 && candidates.distinct() == candidates && candidates.all { it.isNotBlank() && it != "direct" && it != AUTOMATIC }) { "自动候选池须包含不重复的代理节点，最多 32 个，不允许直连" }
            if (selected == AUTOMATIC) {
                require(policy.health.enabled) { "自动组需要启用健康探测" }
                require(candidates.isNotEmpty()) { "请先选择自动组允许使用的候选节点" }
            }
        }
        validateCandidates(policy.defaultOutbound, policy.defaultAutomaticCandidates)
        require(policy.groups.size <= 32) { "最多创建 32 个分组" }
        require(policy.groups.map { it.id }.distinct().size == policy.groups.size) { "分组 ID 重复" }
        require(policy.groups.map { it.name.lowercase(Locale.ROOT) }.distinct().size == policy.groups.size) { "分组名称重复" }
        policy.groups.forEach { group ->
            require(group.id.matches(idPattern) && group.id != "default") { "无效分组 ID" }
            require(group.name.isNotBlank() && group.name.length <= 40) { "分组名称须为 1–40 个字符" }
            require(group.outbound.isNotBlank()) { "请选择 ${group.name} 的代理" }
            validateCandidates(group.outbound, group.automaticCandidates)
            require(group.domains.isNotEmpty() || effectivePackages(group).isNotEmpty()) { "每组至少填写一个域名或选择一个应用" }
            if (group.domains.isNotEmpty()) require(normalizeDomains(group.domains.joinToString("\n")) == group.domains) { "请使用规范化后的域名" }
            require(normalizePackages(group.packages.joinToString("\n")) == group.packages) { "请使用规范化后的应用包名" }
        }
        // Overlaps between groups would make the later group ineffective.
        policy.groups.forEachIndexed { index, group ->
            policy.groups.take(index).forEach { earlier ->
                require(effectivePackages(group).none { it in effectivePackages(earlier) }) { "${group.name} 与 ${earlier.name} 选择了相同应用，请只保留一个匹配分组" }
                require(group.domains.none { domain -> earlier.domains.any { previous ->
                    domain == previous || domain.endsWith(".$previous") || previous.endsWith(".$domain")
                } }) { "${group.name} 的域名与 ${earlier.name} 重叠，请放在同一个组中" }
            }
        }
    }

    fun encode(policy: LocalRoutingPolicy): String = JSONObject()
        .put("schema_version", 2)
        .put("default_outbound", policy.defaultOutbound)
        .put("default_automatic_candidates", JSONArray(policy.defaultAutomaticCandidates))
        .put("health", policy.health.json())
        .put("preset_revision", policy.presetRevision)
        .put("groups", JSONArray().also { groups -> policy.groups.forEach { group ->
            groups.put(JSONObject().put("id", group.id).put("name", group.name)
                .put("domains", JSONArray(group.domains)).put("outbound", group.outbound)
                .put("include_official_app", group.includeOfficialApp).put("packages", JSONArray(group.packages))
                .put("automatic_candidates", JSONArray(group.automaticCandidates)))
        } }).toString()

    fun decode(content: String): LocalRoutingPolicy {
        val root = JSONObject(content)
        return LocalRoutingPolicy(
            root.getString("default_outbound"),
            objects(root.getJSONArray("groups")).map { group ->
                LocalRoutingGroup(group.getString("id"), group.getString("name"),
                    strings(group.getJSONArray("domains")), group.getString("outbound"),
                    group.optBoolean("include_official_app", true), strings(group.optJSONArray("packages")), strings(group.optJSONArray("automatic_candidates")))
            },
            presetRevision = root.optInt("preset_revision", 0),
            health = HealthPolicy.decode(root.optJSONObject("health")),
            defaultAutomaticCandidates = strings(root.optJSONArray("default_automatic_candidates")),
        ).also(::validate)
    }

    fun render(content: String, policy: LocalRoutingPolicy, controlPlaneServer: String = "", includeGeoRules: Boolean = true): LocalRoutingResult {
        validate(policy)
        val root = JSONObject(content)
        // Android's mixed stack still sends TCP through the vendor kernel. Use
        // libbox's userspace TCP/UDP stack consistently across Wi-Fi handovers.
        objects(root.optJSONArray("inbounds")).filter { it.optString("type") == "tun" }
            .forEach { it.put("stack", "gvisor") }
        val nodes = availableNodes(content)
        val nodeTags = nodes.map { it.tag }.toSet()
        val warnings = mutableListOf<String>()

        val outbounds = root.optJSONArray("outbounds") ?: JSONArray().also { root.put("outbounds", it) }
        val usedTags = objects(outbounds).map { it.optString("tag") }.toMutableSet()
        require("direct" !in usedTags || objects(outbounds).any {
            it.optString("tag") == "direct" && it.optString("type") == "direct"
        }) { "服务器的 direct 标签被其他出站占用" }
        if ("direct" !in usedTags) {
            outbounds.put(JSONObject().put("type", "direct").put("tag", "direct"))
            usedTags.add("direct")
        }
        fun allocateTag(base: String, used: MutableSet<String>): String {
            var tag = base
            while (!used.add(tag)) tag += "-local"
            return tag
        }
        val choices = nodes.map { it.tag } + "direct"
        val selections = linkedMapOf<String, String>()
        val automaticGroups = linkedMapOf<String, List<String>>()
        val blockedGroups = linkedSetOf<String>()
        fun selector(id: String, name: String, selected: String, candidates: List<String>): String {
            val tag = allocateTag(TAG_PREFIX + id, usedTags)
            val allowed = if (selected == AUTOMATIC) candidates.filter { it in nodeTags }.also { automaticGroups[tag] = it } else choices
            val resolved = when {
                selected == AUTOMATIC && allowed.isNotEmpty() -> allowed.first()
                selected == "direct" || selected in nodeTags -> selected
                else -> {
                    blockedGroups += tag
                    warnings += if (selected == AUTOMATIC) "$name 的候选池已无可用节点，已阻断该组连接，请重新选择候选池"
                        else "$name 的固定节点「$selected」已不在配置中，已阻断该组连接，不会切换其他出口"
                    "direct" // A valid dormant selector; explicit route and DNS reject rules make it unreachable.
                }
            }
            selections[tag] = resolved
            outbounds.put(JSONObject().put("type", "selector").put("tag", tag)
                .put("outbounds", JSONArray(allowed.ifEmpty { listOf("direct") })).put("default", resolved)
                .put("interrupt_exist_connections", true))
            return tag
        }
        val defaultTag = selector("default", "默认代理", policy.defaultOutbound, policy.defaultAutomaticCandidates)
        val groupTags = policy.groups.associate { it.id to selector(it.id, it.name, it.outbound, it.automaticCandidates) }
        fun routeTo(rule: JSONObject, tag: String): JSONObject =
            if (tag in blockedGroups) rule.put("action", "reject") else rule.put("outbound", tag)

        val route = root.optJSONObject("route") ?: JSONObject().also { root.put("route", it) }
        val ruleSets = route.optJSONArray("rule_set") ?: JSONArray().also { route.put("rule_set", it) }
        val existingRuleSets = objects(ruleSets).map { it.optString("tag") }.toSet()
        if (includeGeoRules) listOf("geosite-private", "geosite-cn", "geoip-cn").forEach { tag ->
            if (tag !in existingRuleSets) {
                val path = if (tag.startsWith("geosite-")) "geosite/${tag.removePrefix("geosite-")}" else "geoip/cn"
                ruleSets.put(JSONObject().put("type", "remote").put("tag", tag).put("format", "binary")
                    .put("url", "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/$path.srs")
                    .put("download_detour", "direct").put("update_interval", "7d"))
            }
        }

        val originalRules = objects(route.optJSONArray("rules"))
        val endpointTags = objects(root.optJSONArray("endpoints")).map { it.optString("tag") }.toSet()
        val proxyRouteTags = objects(outbounds).filter { it.optString("type") !in setOf("direct", "block", "dns") }
            .map { it.optString("tag") }.toSet()
        val rules = JSONArray()
        // Sniff and DNS hijacking must run before domain routes. Preserve management tunnels.
        originalRules.filter { it.optString("action") in setOf("sniff", "hijack-dns", "resolve") }
            .forEach(rules::put)
        if (originalRules.none { it.optString("action") == "sniff" }) rules.put(JSONObject().put("action", "sniff"))
        if (originalRules.none { it.optString("action") == "hijack-dns" }) {
            rules.put(JSONObject().put("protocol", "dns").put("action", "hijack-dns"))
        }
        val controlHost = runCatching { URI(controlPlaneServer).host?.removeSurrounding("[", "]") }.getOrNull()
        if (!controlHost.isNullOrBlank()) {
            val key = if (controlHost.contains(':') || controlHost.matches(Regex("[0-9.]+"))) "ip_cidr" else "domain"
            val host = if (key == "ip_cidr") "$controlHost/${if (controlHost.contains(':')) 128 else 32}" else controlHost
            rules.put(JSONObject().put(key, JSONArray(listOf(host))).put("outbound", "direct"))
        }
        originalRules.filter { it.optString("outbound") in endpointTags }.forEach(rules::put)
        // Management and explicit private-network tunnels stay reachable before application rules.
        // Separate application/domain rules express OR; putting both in one rule would mean AND.
        policy.groups.forEach { group ->
            effectivePackages(group).takeIf { it.isNotEmpty() }?.let { packages ->
                rules.put(routeTo(JSONObject().put("package_name", JSONArray(packages)), groupTags.getValue(group.id)))
            }
        }
        rules.put(JSONObject().put("ip_is_private", true).put("outbound", "direct"))
        policy.groups.filter { it.domains.isNotEmpty() }.forEach { group ->
            rules.put(routeTo(JSONObject().put("domain_suffix", JSONArray(group.domains)), groupTags.getValue(group.id)))
        }
        if (includeGeoRules) rules.put(JSONObject().put("rule_set", JSONArray(listOf("geosite-private", "geosite-cn", "geoip-cn")))
            .put("outbound", "direct"))
        // Client groups supersede centrally pinned proxy exits. Keep other direct,
        // reject and special rules, including nested logical rules, as provisioned.
        originalRules.filter { rule ->
            rule.optString("action") !in setOf("sniff", "hijack-dns", "resolve") &&
                rule.optString("outbound") !in endpointTags &&
                rule.optString("outbound") !in proxyRouteTags &&
                (!rule.has("outbound") || rule.optString("outbound") in usedTags)
        }.forEach(rules::put)
        if (defaultTag in blockedGroups) rules.put(JSONObject().put("action", "reject"))
        route.put("rules", rules).put("final", defaultTag).put("find_process", true)

        val dns = root.optJSONObject("dns") ?: JSONObject().also { root.put("dns", it) }
        val servers = dns.optJSONArray("servers") ?: JSONArray().also { dns.put("servers", it) }
        // Repair cached typed DNS configs from the old explicit-direct profile.
        val emptyDirectTags = objects(outbounds).filter { outbound ->
            outbound.optString("type") == "direct" && outbound.keys().asSequence().all { it in setOf("type", "tag") }
        }.map { it.optString("tag") }.toSet()
        objects(servers).filter { it.optString("type") in setOf("https", "tls", "tcp", "udp", "quic", "h3", "local") &&
            it.optString("detour") in emptyDirectTags }.forEach { it.remove("detour") }
        val dnsTags = objects(servers).map { it.optString("tag") }.toMutableSet()
        fun dnsServer(baseTag: String, detour: String?): String {
            val tag = allocateTag(baseTag, dnsTags)
            val server = JSONObject().put("type", "https").put("tag", tag)
                .put("server", if (detour == null) "223.5.5.5" else "dns.google")
                .put("server_port", 443).put("path", "/dns-query")
                .put("tls", JSONObject().put("enabled", true)
                    .put("server_name", if (detour == null) "dns.alidns.com" else "dns.google"))
            // Keep the DoH hostname on the detour. HTTP exits can reach domains
            // while refusing a literal DNS IP; resolving here would undo this.
            if (detour != null) server.put("detour", detour)
            servers.put(server)
            return tag
        }
        val directDns = dnsServer(TAG_PREFIX + "dns-direct", null)
        val nodeTypes = nodes.associate { it.tag to it.type }
        fun useFakeIP(tag: String) = tag !in blockedGroups &&
            (nodeTypes[selections[tag]] == "http" || automaticGroups[tag].orEmpty().any { nodeTypes[it] == "http" })
        // Keep the mapping store present across switches to non-HTTP/direct
        // nodes: browsers may still hold addresses returned before the switch.
        val fakeDns = objects(servers).firstOrNull { it.optString("type") == "fakeip" }?.getString("tag")
            ?: allocateTag(TAG_PREFIX + "dns-fakeip", dnsTags).also { tag ->
                servers.put(JSONObject().put("type", "fakeip").put("tag", tag)
                    .put("inet4_range", "198.18.0.0/15").put("inet6_range", "fc00::/18"))
            }
        val experimental = root.optJSONObject("experimental") ?: JSONObject().also { root.put("experimental", it) }
        val cache = experimental.optJSONObject("cache_file") ?: JSONObject().also { experimental.put("cache_file", it) }
        cache.put("enabled", true).put("store_fakeip", true)
        val defaultDns = if (selections[defaultTag] == "direct") directDns
            else dnsServer(TAG_PREFIX + "dns-default", defaultTag)
        val tunInbounds = objects(root.optJSONArray("inbounds")).filter { it.optString("type") == "tun" }
        val ipv4OnlyTun = tunInbounds.isNotEmpty() && tunInbounds.none {
            it.opt("address")?.toString()?.contains(':') == true || it.opt("inet6_address")?.toString()?.contains(':') == true
        }
        // DNS rule strategy is deprecated in 1.14 and cannot combine with query_type.
        // Answer unsupported AAAA locally instead of handing it to another resolver.
        val suppressedFakeTypes = listOf("HTTPS", "SVCB") + if (ipv4OnlyTun) listOf("AAAA") else emptyList()
        fun fakeAddressRule(rule: JSONObject): JSONObject = rule
            .put("query_type", JSONArray(if (ipv4OnlyTun) listOf("A") else listOf("A", "AAAA")))
            .put("action", "route").put("server", fakeDns)
        val dnsRules = JSONArray()
        val groupDnsServers = policy.groups.associate { group ->
            val tag = groupTags.getValue(group.id)
            group.id to if (selections[tag] == "direct") directDns else dnsServer(TAG_PREFIX + "dns-" + group.id, tag)
        }
        fun addGroupDnsRule(group: LocalRoutingGroup, field: String, values: List<String>) {
            val tag = groupTags.getValue(group.id)
            if (tag in blockedGroups) {
                dnsRules.put(JSONObject().put(field, JSONArray(values)).put("action", "predefined").put("rcode", "REFUSED"))
                return
            }
            if (useFakeIP(tag)) {
                // Do not let HTTPS/SVCB address hints bypass the FakeIP mapping.
                dnsRules.put(JSONObject().put(field, JSONArray(values)).put("query_type", JSONArray(suppressedFakeTypes))
                    .put("action", "predefined").put("rcode", "NOERROR"))
                dnsRules.put(fakeAddressRule(JSONObject().put(field, JSONArray(values))))
            }
            dnsRules.put(JSONObject().put(field, JSONArray(values)).put("action", "route").put("server", groupDnsServers.getValue(group.id)))
        }
        if (!controlHost.isNullOrBlank() && !controlHost.contains(':') && !controlHost.matches(Regex("[0-9.]+"))) {
            dnsRules.put(JSONObject().put("domain", JSONArray(listOf(controlHost)))
                .put("action", "route").put("server", directDns))
        }
        // Preserve centrally provisioned DNS routing to WireGuard/private-network DNS servers.
        val endpointDns = objects(servers).filter { it.optString("detour") in endpointTags }.map { it.optString("tag") }.toSet()
        objects(dns.optJSONArray("rules")).filter { it.optString("server") in endpointDns }.forEach(dnsRules::put)
        policy.groups.forEach { group ->
            effectivePackages(group).takeIf { it.isNotEmpty() }?.let { addGroupDnsRule(group, "package_name", it) }
        }
        policy.groups.filter { it.domains.isNotEmpty() }.forEach { group -> addGroupDnsRule(group, "domain_suffix", group.domains) }
        if (includeGeoRules) dnsRules.put(JSONObject().put("rule_set", JSONArray(listOf("geosite-private", "geosite-cn")))
            .put("action", "route").put("server", directDns))
        dnsRules.put(JSONObject().put("domain_suffix", JSONArray(listOf("lan", "local")))
            .put("action", "route").put("server", directDns))
        if (useFakeIP(defaultTag)) {
            dnsRules.put(JSONObject().put("query_type", JSONArray(suppressedFakeTypes))
                .put("action", "predefined").put("rcode", "NOERROR"))
            dnsRules.put(fakeAddressRule(JSONObject()))
        }
        // Routing DNS decisions now belong to the local policy; retain blocking
        // and other non-route DNS actions from the server.
        objects(dns.optJSONArray("rules")).filter {
            it.optString("action") !in setOf("", "route", "route-options") && it.optString("server") !in endpointDns
        }.forEach(dnsRules::put)
        if (defaultTag in blockedGroups) dnsRules.put(JSONObject().put("action", "predefined").put("rcode", "REFUSED"))
        dns.put("rules", dnsRules).put("final", defaultDns).put("reverse_mapping", true)
        // sing-box 1.14 always separates caches by server; remove the legacy option.
        dns.remove("independent_cache")
        // Resolving the proxy node via its own group would create a DNS loop.
        route.put("default_domain_resolver", JSONObject().put("server", directDns).put("strategy", "prefer_ipv4"))

        return LocalRoutingResult(
            root.toString(),
            LocalRoutingSnapshot(policy, nodes + ProxyItemSnapshot("direct", "direct", 0, 0) +
                if (nodes.isEmpty()) emptyList() else listOf(ProxyItemSnapshot(AUTOMATIC, "automatic", 0, 0)),
                defaultTag, groupTags, warnings, selections, automaticGroups, blockedGroups),
        )
    }

    /** HTTP/FakeIP and direct DNS transitions require a reload, not just a selector command. */
    fun sameDnsConfiguration(previous: String, next: String): Boolean =
        JSONObject(previous).optJSONObject("dns").toString() == JSONObject(next).optJSONObject("dns").toString()

    fun sameSelectorCandidates(previous: String, next: String): Boolean {
        fun selectors(content: String) = objects(JSONObject(content).optJSONArray("outbounds"))
            .filter { it.optString("type") == "selector" && it.optString("tag").startsWith(TAG_PREFIX) }
            .associate { it.getString("tag") to strings(it.optJSONArray("outbounds")) }
        return selectors(previous) == selectors(next)
    }

    /** Restore these through libbox after every start/reload, before reporting ready. */
    fun selectionsFromConfig(content: String): Map<String, String> =
        objects(JSONObject(content).optJSONArray("outbounds"))
            .filter { it.optString("type") == "selector" && it.optString("tag").startsWith(TAG_PREFIX) && it.has("default") }
            .associate { it.getString("tag") to it.getString("default") }

    private fun objects(array: JSONArray?): List<JSONObject> =
        (0 until (array?.length() ?: 0)).mapNotNull { array?.optJSONObject(it) }

    private fun strings(array: JSONArray?): List<String> =
        (0 until (array?.length() ?: 0)).mapNotNull { array?.optString(it)?.takeIf(String::isNotBlank) }
}
