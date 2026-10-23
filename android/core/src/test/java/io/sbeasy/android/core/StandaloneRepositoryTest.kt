package io.sbeasy.android.core

import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class StandaloneRepositoryTest {
    private val enrollment = Enrollment("https://center.example", "host", "phone", "agent-secret", "profile", "managed")
    private val first = "trojan://secret@one.example:443#Stable"
    private val second = "trojan://newsecret@two.example:443#Stable"
    private val credentialStore = MemoryEnrollment(enrollment)
    private val managed = MemoryConfig()
    private val local = MemoryConfig()
    private val managedRouting = MemoryRouting()
    private val localRouting = MemoryRouting()
    private val records = MemorySubscriptions()
    private var download = first
    private var downloads = 0
    private var centerCalls = 0
    private val forbiddenCenter = object : AgentControlPlane {
        private fun unexpected(): Nothing { centerCalls++; error("Standalone mode must not contact the center") }
        override fun enroll(rawUri: String, device: JSONObject, allowInsecureLocalHttp: Boolean): Enrollment = unexpected()
        override fun fetchConfig(enrollment: Enrollment, etag: String?, force: Boolean): ConfigFetchResult = unexpected()
        override fun reportStatus(enrollment: Enrollment, body: JSONObject) = unexpected()
        override fun commands(enrollment: Enrollment): List<AgentCommand> = unexpected()
        override fun acknowledge(enrollment: Enrollment, command: AgentCommand, success: Boolean, result: String) = unexpected()
        override fun reportTelemetry(enrollment: Enrollment, body: JSONObject) = unexpected()
        override fun networkSnapshot(): JSONObject = unexpected()
        override fun uploadDiagnostics(enrollment: Enrollment, body: JSONObject): String = unexpected()
        override fun uploadCapture(enrollment: Enrollment, digest: String, data: ByteArray, wifiOnly: Boolean) = unexpected()
        override fun reportLatencies(enrollment: Enrollment, values: Map<String, Int?>) = unexpected()
    }
    private fun repository() = AgentRepository(credentialStore, managed, forbiddenCenter, "install", managedRouting, local, localRouting, records,
        SubscriptionSource { _, _ -> downloads++; SubscriptionFetcher.Download(download, SubscriptionQuota(total = 1000)) })

    @Before fun prepare() {
        VpnRuntimeState.disconnected()
        RuntimeObservability.resetRuntime()
        RuntimeObservability.clearLogs()
        RuntimeBridge.validator = object : ConfigValidator { override fun validate(content: String) { JSONObject(content) } }
    }
    @After fun cleanup() { RuntimeBridge.validator = null; RuntimeBridge.control = null; VpnRuntimeState.disconnected() }

    @Test fun managedHttpAuthorizationIsExplicitLocalAndStoredOnlyWithEnrollment() = runBlocking {
        credentialStore.value = enrollment.copy(server = "http://192.168.20.1:51821")
        val repo = repository()
        assertFalse(repo.state.value.enrollment!!.allowInsecureLocalHttp)
        repo.allowManagedLocalHttp(true)
        assertTrue(credentialStore.value!!.allowInsecureLocalHttp)
        repo.allowManagedLocalHttp(false)
        assertFalse(credentialStore.value!!.allowInsecureLocalHttp)
        credentialStore.value = enrollment.copy(server = "http://public.example")
        assertTrue(runCatching { repository().allowManagedLocalHttp(true) }.isFailure)
        credentialStore.value = enrollment.copy(server = "http://192.168.20.1:51821")
        val independent = repository(); independent.switchMode(ClientMode.STANDALONE)
        assertTrue(runCatching { independent.allowManagedLocalHttp(true) }.isFailure)
        assertEquals(0, centerCalls)
    }

    @Test fun freshStandaloneImportStartsFromLocalCacheAndNeverUsesEnrollment() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Local", first, false, 0, false)
        assertNotNull(repo.activeConfig())
        assertNull(repo.state.value.enrollment)
        assertEquals(enrollment, credentialStore.value)
        val restarted = repository()
        assertEquals(repo.activeConfig()?.etag, restarted.activeConfig()?.etag)
        restarted.runControlCycle("1", "1")
        restarted.reportTelemetry()
        restarted.uploadCaptures(manual = false)
        assertTrue(runCatching { restarted.uploadCaptures() }.isFailure)
        assertEquals(0, downloads)
        assertEquals(0, centerCalls)
        assertEquals("local-subscriptions", restarted.activeConfig()?.ruleSource)
        assertNull(managed.active())
    }

    @Test fun modeSwitchPreservesBothPoliciesAndRejectsSwitchWhileRunning() = runBlocking {
        val managedBase = SubscriptionParser.baseConfig(listOf(LocalSubscription("center", "center", first, false, nodes = SubscriptionParser.parse(first).nodes.map { it.toString() })))
        managed.value = managedBase.copy(ruleSource = "profile")
        val policy = LocalRouting.defaults(managedBase.content).copy(defaultOutbound = "direct")
        managedRouting.value = policy
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "local", first, false, 0, false)
        val localPolicy = repo.routing.value.policy
        RuntimeObservability.appendLogs(listOf(RuntimeLog(1, "standalone-secret-metadata")))
        VpnRuntimeState.connected(repo.activeConfig())
        assertTrue(runCatching { repo.switchMode(ClientMode.MANAGED) }.isFailure)
        VpnRuntimeState.failed("Recovery still owns the VPN service")
        RuntimeBridge.control = HealthRuntime()
        assertTrue(runCatching { repo.switchMode(ClientMode.MANAGED) }.isFailure)
        RuntimeBridge.control = null
        VpnRuntimeState.disconnected()
        repo.switchMode(ClientMode.MANAGED)
        assertEquals(enrollment, repo.state.value.enrollment)
        assertTrue(RuntimeObservability.logs.value.isEmpty())
        assertEquals(policy, repo.routing.value.policy)
        repo.switchMode(ClientMode.STANDALONE)
        assertEquals(localPolicy, repo.routing.value.policy)
        assertNull(repo.state.value.enrollment)
    }

    @Test fun invalidRefreshRetainsNodesConfigAndReportsFailure() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Remote", "https://example/sub", true, 15, false)
        val before = repo.activeConfig()
        val nodes = repo.subscriptions.value.single().nodes
        download = "ssr://unsupported"
        repo.refreshSubscriptions(force = true)
        assertEquals(before?.etag, repo.activeConfig()?.etag)
        assertEquals(nodes, repo.subscriptions.value.single().nodes)
        assertNotNull(repo.subscriptions.value.single().error)
        assertEquals(SyncPhase.ERROR, repo.state.value.syncPhase)
    }

    @Test fun missingFixedExitRejectsRefreshInsteadOfSelectingAnotherNode() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Remote", "https://example/sub", true, 15, false)
        val before = repo.activeConfig()
        download = "trojan://secret@other.example:443#Different"
        assertTrue(runCatching { repo.refreshSubscriptions(force = true) }.isFailure)
        assertEquals(before?.etag, repo.activeConfig()?.etag)
        assertTrue(repo.subscriptions.value.single().error.orEmpty().contains("固定出口"))
    }

    @Test fun diskFailureRollsBackRunningCoreAndSubscriptionStore() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Remote", "https://example/sub", true, 15, false)
        val before = repo.activeConfig()!!
        val beforeNodes = records.value.single().nodes
        val applied = mutableListOf<ManagedConfig>()
        RuntimeBridge.control = object : RuntimeControl {
            override suspend fun applyConfiguration(config: ManagedConfig) { applied += config }
            override suspend fun restart() = Unit
            override suspend fun selectOutbound(groupTag: String, outboundTag: String) = Unit
            override suspend fun urlTest(groupTag: String) = Unit
            override suspend fun clearLogs() = Unit
        }
        local.failNextPromotion = true
        download = second
        assertTrue(runCatching { repo.refreshSubscriptions(force = true) }.isFailure)
        assertEquals(before.etag, repo.activeConfig()?.etag)
        assertEquals(beforeNodes, records.value.single().nodes)
        assertEquals(before.content, applied.last().content)
        assertEquals(2, applied.size)
    }

    @Test fun validRefreshKeepsGroupsAndAutomaticCadence() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Remote", "https://example/sub", true, 360, false)
        val oldPolicy = repo.routing.value.policy!!
        repo.updateLocalRouting(oldPolicy.copy(groups = oldPolicy.groups + LocalRoutingGroup("custom", "Custom", listOf("custom.example"), oldPolicy.defaultOutbound, false)))
        repo.refreshSubscriptions()
        assertEquals(1, downloads)
        download = second
        repo.refreshSubscriptions(force = true)
        assertEquals(2, downloads)
        assertEquals("custom", repo.routing.value.policy!!.groups.last().id)
        assertTrue(repo.activeConfig()!!.content.contains("two.example"))
    }

    @Test fun removingLastSubscriptionRequiresStoppedVpnAndClearsStaleConfig() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Local", first, false, 0, false)
        val id = repo.subscriptions.value.single().id
        VpnRuntimeState.connected(repo.activeConfig())
        assertTrue(runCatching { repo.removeSubscription(id) }.isFailure)
        VpnRuntimeState.disconnected()
        repo.removeSubscription(id)
        assertNull(repo.activeConfig())
        assertNull(local.active())
        assertTrue(records.value.isEmpty())
        assertNull(localRouting.value)
    }


    @Test fun healthCycleSwitchesOnlyExplicitAutomaticGroupsAndHonorsCadence() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Local", first + "\n" + second.replace("#Stable", "#Other"), false, 0, false)
        val initial = repo.routing.value
        val nodes = initial.availableNodes.filter { it.type !in setOf("direct", "automatic") }.map { it.tag }
        repo.updateLocalRouting(initial.policy!!.copy(defaultAutomaticCandidates = nodes))
        repo.selectOutbound(initial.defaultTag, LocalRouting.AUTOMATIC)
        val snapshot = repo.routing.value
        val fixedChoices = snapshot.policy!!.groups.map { it.outbound }
        val runtime = HealthRuntime().apply { results = mapOf(nodes[0] to null, nodes[1] to 70) }
        RuntimeBridge.control = runtime
        VpnRuntimeState.connected(repo.activeConfig())
        assertTrue(repo.runHealthCycle())
        assertEquals(listOf(snapshot.defaultTag to nodes[1]), runtime.selections)
        assertEquals(fixedChoices, repo.routing.value.policy!!.groups.map { it.outbound })
        assertTrue(repo.health.value.warnings.any { it.contains("固定节点") })
        assertFalse(repo.runHealthCycle())
        assertEquals(2, runtime.probes.size)
        repo.invalidateHealth()
        assertTrue(repo.runHealthCycle())
        assertEquals(2, runtime.selections.size)
        runtime.results = emptyMap()
        assertTrue(repo.runHealthCycle(force = true))
        assertEquals(2, runtime.selections.size)
        assertTrue(repo.health.value.warnings.any { it.contains("全部候选") })
        assertEquals(0, centerCalls)
    }

    @Test fun healthCycleUsesConfiguredDeadlineAndDiscardsOldRuntimeResults() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Local", first + "\n" + second.replace("#Stable", "#Other"), false, 0, false)
        repo.selectOutbound(repo.routing.value.defaultTag, LocalRouting.AUTOMATIC)
        repo.updateLocalRouting(repo.routing.value.policy!!.copy(health = HealthPolicy(probeUrl = "https://probe.example/check", timeoutMillis = 900, intervalSeconds = 60)))
        val runtime = HealthRuntime().apply { incrementGeneration = true }
        RuntimeBridge.control = runtime
        VpnRuntimeState.connected(repo.activeConfig())
        assertFalse(repo.runHealthCycle(force = true))
        assertTrue(runtime.probes.all { it.second == "https://probe.example/check" && it.third == 900 })
        assertTrue(runtime.selections.isEmpty())
        assertFalse(repo.health.value.checking)
        assertEquals(0L, repo.health.value.checkedAtMillis)
    }

    @Test fun healthSettingsPersistAndFixedPolicyCanDisablePeriodicChecks() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Local", first, false, 0, false)
        val requested = HealthPolicy(enabled = false, intervalSeconds = 70, timeoutMillis = 800, toleranceMillis = 15)
        repo.updateLocalRouting(repo.routing.value.policy!!.copy(health = requested))
        assertEquals(requested, repository().routing.value.policy!!.health)
        val runtime = HealthRuntime()
        RuntimeBridge.control = runtime
        VpnRuntimeState.connected(repo.activeConfig())
        assertFalse(repo.runHealthCycle())
        assertTrue(runtime.probes.isEmpty())
        assertTrue(repo.runHealthCycle(force = true))
        assertTrue(runtime.selections.isEmpty())
    }

    @Test fun runtimeOverlayFailureRollsBackWithoutChangingSavedConfiguration() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "local", first, false, 0, false)
        val config = repo.activeConfig()
        val runtime = HealthRuntime().apply { failNextApply = true }
        RuntimeBridge.control = runtime
        VpnRuntimeState.connected(config)
        var attached = false
        assertTrue(runCatching { repo.updateRuntimeOverlay(true, { attached = true }, { attached = false }) }.isFailure)
        assertFalse(attached)
        assertEquals(2, runtime.applyCount)
        assertEquals(config, repo.activeConfig())
        RuntimeBridge.control = null
        assertTrue(runCatching { repo.updateRuntimeOverlay(true, { attached = true }, { attached = false }) }.isFailure)
        assertFalse(attached)
    }

    @Test fun preferencesRoundTripKeepsEnrollmentAndDeviceAppsWhileReplacingPortableRules() = runBlocking {
        val repo = repository()
        repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Local", first, false, 0, false)
        val policy = repo.routing.value.policy!!
        repo.updateLocalRouting(policy.copy(groups = policy.groups + LocalRoutingGroup("app-only", "Local app", emptyList(), policy.defaultOutbound, false, listOf("com.example.local"))))
        val exported = repo.exportPreferences()
        assertFalse(exported.contains("agent-secret")); assertFalse(exported.contains("com.example.local")); assertFalse(exported.contains("include_official_app"))
        val preview = repo.previewPreferences(exported)
        val before = repo.routing.value.policy
        repo.importPreferences(preview)
        assertEquals(before, repo.routing.value.policy)
        assertEquals(enrollment, credentialStore.value)
        assertEquals(ClientMode.STANDALONE, repo.state.value.mode)
        assertEquals(0, centerCalls)
    }

    @Test fun stalePreviewAndRunningVpnRejectWithoutOverwritingPreferences() = runBlocking {
        val repo = repository(); repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Local", first, false, 0, false)
        val payload = repo.exportPreferences(); val preview = repo.previewPreferences(payload)
        repo.updateLocalRouting(repo.routing.value.policy!!.copy(defaultOutbound = "direct"))
        assertTrue(runCatching { repo.importPreferences(preview) }.exceptionOrNull()?.message.orEmpty().contains("已变化"))
        assertEquals("direct", repo.routing.value.policy!!.defaultOutbound)
        VpnRuntimeState.connected(repo.activeConfig())
        assertTrue(runCatching { repo.previewPreferences(payload) }.isFailure)
        assertTrue(runCatching { repo.importPreferences(preview) }.isFailure)
    }

    @Test fun failedPreferenceDiskCommitRollsBackAllStores() = runBlocking {
        val repo = repository(); repo.switchMode(ClientMode.STANDALONE)
        repo.saveSubscription(null, "Local", first, false, 0, false)
        val oldRecords = records.value; val oldPolicy = localRouting.value; val oldConfig = local.value
        val payload = PreferencesPayload.decode(repo.exportPreferences())
        val replacement = payload.copy(subscriptions = payload.subscriptions.map { it.copy(name = "Imported") },
            standaloneRouting = payload.standaloneRouting!!.copy(defaultOutbound = "direct"))
        val preview = repo.previewPreferences(PreferencesPayload.encode(replacement))
        local.failNextPromotion = true
        assertTrue(runCatching { repo.importPreferences(preview) }.isFailure)
        assertEquals(oldRecords, records.value); assertEquals(oldPolicy, localRouting.value); assertEquals(oldConfig, local.value)
        assertEquals(oldRecords, repo.subscriptions.value); assertEquals(oldPolicy, repo.routing.value.policy)
    }

    private class HealthRuntime : RuntimeControl {
        var results = emptyMap<String, Int?>()
        var incrementGeneration = false
        var generation = 0L
        var failNextApply = false
        var applyCount = 0
        override val configurationGeneration get() = generation
        val selections = java.util.Collections.synchronizedList(mutableListOf<Pair<String, String>>())
        val probes = java.util.Collections.synchronizedList(mutableListOf<Triple<String, String, Int>>())
        override suspend fun probeOutbound(tag: String, url: String, timeoutMillis: Int): NodeHealthResult {
            probes += Triple(tag, url, timeoutMillis)
            if (incrementGeneration) generation++
            return NodeHealthResult(tag, results[tag], if (results[tag] == null) "failed" else null)
        }
        override suspend fun applyConfiguration(config: ManagedConfig) {
            applyCount++
            if (failNextApply) { failNextApply = false; error("Core rejected overlay") }
        }
        override suspend fun restart() = Unit
        override suspend fun selectOutbound(groupTag: String, outboundTag: String) { selections += groupTag to outboundTag }
        override suspend fun urlTest(groupTag: String) = Unit
        override suspend fun clearLogs() = Unit
    }

    private class MemoryEnrollment(var value: Enrollment?) : EnrollmentStorage {
        override fun load() = value
        override fun save(enrollment: Enrollment) { value = enrollment }
        override fun clear() { value = null }
    }
    private class MemoryConfig : ConfigurationStorage {
        var value: ManagedConfig? = null
        var next: ManagedConfig? = null
        var previous: ManagedConfig? = null
        var failNextPromotion = false
        override fun active() = value
        override fun candidate() = next
        override fun saveCandidate(config: ManagedConfig) { next = config }
        override fun promoteCandidate(): ManagedConfig {
            if (failNextPromotion) { failNextPromotion = false; error("Disk full") }
            previous = value; value = next; next = null; return requireNotNull(value)
        }
        override fun rollback(): ManagedConfig? { value = previous; return value }
        override fun clear() { value = null; next = null; previous = null }
    }
    private class MemoryRouting : RoutingStorage {
        var value: LocalRoutingPolicy? = null
        override fun load() = value
        override fun save(policy: LocalRoutingPolicy) { value = policy }
        override fun clear() { value = null }
    }
    private class MemorySubscriptions : SubscriptionStorage {
        var value = emptyList<LocalSubscription>()
        var selectedMode = ClientMode.MANAGED
        override fun mode() = selectedMode
        override fun setMode(mode: ClientMode) { selectedMode = mode }
        override fun load() = value
        override fun save(subscriptions: List<LocalSubscription>) { value = subscriptions }
    }
}
