package io.sbeasy.android.core

import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class ManagedConfigSyncTest {
    private val enrollment = Enrollment("https://center.example", "device", "Phone", "secret", "default", "Default")
    private val content = """{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""
    private class Memory : ConfigSyncStorage {
        var value: JSONObject? = null
        override fun load() = value?.let { JSONObject(it.toString()) }
        override fun save(value: JSONObject) { this.value = JSONObject(value.toString()) }
        override fun clear() { value = null }
    }
    private inner class Center : AgentControlPlane {
        var remote = JSONObject().put("base_version", 100L).put("patch_version", 0L).put("base", JSONObject(content))
            .put("config", JSONObject(content)).put("patch", JSONObject()).put("agent_settings", JSONObject()).put("etag", "abc")
        var uploads = 0
        var disconnectAfterCommit = false
        override fun fetchConfigState(enrollment: Enrollment) = JSONObject(remote.toString())
        override fun putConfigState(enrollment: Enrollment, body: JSONObject): JSONObject {
            if (body.getLong("base_version") != remote.getLong("base_version") || body.getLong("patch_version") != remote.getLong("patch_version"))
                throw ControlPlaneException("conflict", 409)
            uploads++
            remote.put("patch", body.getJSONObject("patch")).put("agent_settings", body.getJSONObject("agent_settings")).put("patch_version", 200L)
            if (disconnectAfterCommit) throw java.io.IOException("lost acknowledgement")
            return JSONObject(remote.toString())
        }
        override fun enroll(rawUri: String, device: JSONObject, allowInsecureLocalHttp: Boolean): Enrollment = error("unused")
        override fun fetchConfig(enrollment: Enrollment, etag: String?, force: Boolean): ConfigFetchResult = error("unused")
        override fun reportStatus(enrollment: Enrollment, body: JSONObject) {}
        override fun commands(enrollment: Enrollment) = emptyList<AgentCommand>()
        override fun acknowledge(enrollment: Enrollment, command: AgentCommand, success: Boolean, result: String) {}
        override fun reportTelemetry(enrollment: Enrollment, body: JSONObject) {}
        override fun networkSnapshot() = JSONObject()
        override fun uploadDiagnostics(enrollment: Enrollment, body: JSONObject) = ""
        override fun uploadCapture(enrollment: Enrollment, digest: String, data: ByteArray, wifiOnly: Boolean) {}
        override fun reportLatencies(enrollment: Enrollment, values: Map<String, Int?>) {}
    }
    @Test fun unchangedDeviceInheritsDefaultsWithoutUpload() {
        val store = Memory(); val center = Center(); val sync = ManagedConfigSync(store, center)
        sync.synchronize(enrollment, LocalRouting.defaults(content))
        assertEquals(0, center.uploads)
        assertFalse(store.load()!!.has("pending"))
        center.remote.getJSONObject("config").getJSONObject("route").put("final", "new-default")
        center.remote.put("base_version", 300L)
        assertEquals(300L, sync.synchronize(enrollment, null)!!.getLong("base_version"))
    }
    @Test fun outboxSurvivesRestartAndLostAcknowledgement() {
        val store = Memory(); val center = Center(); var sync = ManagedConfigSync(store, center)
        sync.synchronize(enrollment, null)
        sync.queue(enrollment, LocalRouting.defaults(content).copy(presetRevision = 3), content)
        sync = ManagedConfigSync(store, center)
        center.disconnectAfterCommit = true
        assertTrue(runCatching { sync.synchronize(enrollment, null) }.isFailure)
        assertTrue(store.load()!!.has("pending"))
        assertNotNull(sync.synchronize(enrollment, null))
        assertFalse(store.load()!!.has("pending"))
        assertEquals(1, center.uploads)
    }
    @Test fun staleDraftIsRetainedUntilExplicitConflictResolution() {
        val store = Memory(); val center = Center(); val sync = ManagedConfigSync(store, center)
        sync.synchronize(enrollment, null)
        sync.queue(enrollment, LocalRouting.defaults(content).copy(presetRevision = 3), content)
        center.remote.put("patch_version", 500L)
        center.remote.getJSONObject("agent_settings").put("android_routing", JSONObject().put("preset_revision", 4))
        val error = runCatching { sync.synchronize(enrollment, null) }.exceptionOrNull() as ControlPlaneException
        assertEquals(409, error.statusCode)
        assertTrue(store.load()!!.has("pending"))
        assertEquals(4, center.remote.getJSONObject("agent_settings").getJSONObject("android_routing").getInt("preset_revision"))
        sync.resolve(enrollment, false)
        assertEquals(4, sync.policy(sync.synchronize(enrollment, null)!!).presetRevision)
        assertFalse(store.load()!!.has("pending"))
    }
    @Test fun mergePatchDeletesFieldsAndTreatsListsAtomically() {
        val base = JSONObject("""{"a":{"x":1,"y":2},"list":[1,2],"gone":true}""")
        val next = JSONObject("""{"a":{"x":3,"y":2},"list":[2]}""")
        val patch = ConfigMergePatch.diff(base, next)
        assertTrue(patch.isNull("gone"))
        assertFalse(patch.getJSONObject("a").has("y"))
        assertTrue(ConfigMergePatch.equal(next, ConfigMergePatch.apply(base, patch)))
    }
    @After fun cleanupRuntime() { RuntimeBridge.control = null; RuntimeBridge.validator = null; RuntimeObservability.resetRuntime() }

    @Test fun futurePolicyFieldsSurviveLocalRoutingChanges() {
        val store = Memory(); val center = Center(); val sync = ManagedConfigSync(store, center)
        center.remote.getJSONObject("agent_settings").put("future_settings", JSONObject().put("keep", true))
            .put("android_routing", JSONObject().put("future_policy", 7).put("health", JSONObject().put("future_probe", "keep")))
        sync.synchronize(enrollment, null)
        sync.queue(enrollment, LocalRouting.defaults(content).copy(presetRevision = 2), content)
        sync.synchronize(enrollment, null)
        val settings = center.remote.getJSONObject("agent_settings")
        assertTrue(settings.getJSONObject("future_settings").getBoolean("keep"))
        assertEquals(7, settings.getJSONObject("android_routing").getInt("future_policy"))
        assertEquals("keep", settings.getJSONObject("android_routing").getJSONObject("health").getString("future_probe"))
    }

    @Test fun managedSelectorAndCaptureDefaultsReachTheRunningConfiguration() = runBlocking {
        val store = Memory(); val center = Center()
        val raw = """{"outbounds":[{"type":"direct","tag":"direct"},{"type":"direct","tag":"alternate"},{"type":"selector","tag":"remote","outbounds":["direct","alternate"],"default":"direct"}],"route":{"final":"direct"}}"""
        center.remote.put("base", JSONObject(raw)).put("config", JSONObject(raw))
        var active: ManagedConfig? = null; var candidate: ManagedConfig? = null; var storedPolicy: LocalRoutingPolicy? = null
        val configurations = object : ConfigurationStorage {
            override fun active() = active
            override fun candidate() = candidate
            override fun saveCandidate(config: ManagedConfig) { candidate = config }
            override fun promoteCandidate(): ManagedConfig { active = candidate!!; candidate = null; return active!! }
            override fun rollback() = active
            override fun clear() { active = null; candidate = null }
        }
        val routing = object : RoutingStorage {
            override fun load() = storedPolicy
            override fun save(policy: LocalRoutingPolicy) { storedPolicy = policy }
            override fun clear() { storedPolicy = null }
        }
        val credentials = object : EnrollmentStorage {
            override fun load() = enrollment
            override fun save(enrollment: Enrollment) {}
            override fun clear() {}
        }
        val subscriptions = object : SubscriptionStorage {
            override fun mode() = ClientMode.MANAGED
            override fun setMode(mode: ClientMode) {}
            override fun load() = emptyList<LocalSubscription>()
            override fun save(subscriptions: List<LocalSubscription>) {}
        }
        var selectors = JSONObject(); var capture = captureTemplate(CaptureConfig()); var failCapture = false
        val platform = object : PlatformConfigurationStorage {
            override fun selectors() = JSONObject(selectors.toString())
            override fun saveSelectors(value: JSONObject) { selectors = JSONObject(value.toString()) }
            override fun captureTemplate() = JSONObject(capture.toString())
            override fun saveCaptureTemplate(value: JSONObject) {
                if (failCapture) { failCapture = false; error("disk failure") }
                capture = JSONObject(value.toString())
            }
        }
        val liveSelections = mutableMapOf("remote" to "stale-core-cache")
        var applications = 0
        RuntimeBridge.validator = object : ConfigValidator { override fun validate(content: String) { JSONObject(content) } }
        RuntimeBridge.control = object : RuntimeControl {
            override suspend fun applyConfiguration(config: ManagedConfig) { applications++; liveSelections.putAll(managedSelectorDefaults(config.content)) }
            override suspend fun restart() {}
            override suspend fun selectOutbound(groupTag: String, outboundTag: String) { liveSelections[groupTag] = outboundTag }
            override suspend fun urlTest(groupTag: String) {}
            override suspend fun clearLogs() {}
        }
        val repository = AgentRepository(credentials, configurations, center, "installation", routing,
            configurations, routing, subscriptions, syncStorage = store, platformStorage = platform)
        repository.syncConfiguration()
        assertEquals("direct", liveSelections["remote"])
        repository.selectOutbound("remote", "alternate")
        assertEquals("alternate", liveSelections["remote"])
        assertTrue(store.load()!!.has("pending"))
        repository.syncConfiguration()
        assertEquals("alternate", center.remote.getJSONObject("agent_settings").getJSONObject("android_selectors").getString("remote"))
        center.remote.getJSONObject("agent_settings").remove("android_selectors")
        center.remote.put("patch_version", 300L)
        repository.syncConfiguration()
        assertEquals("direct", liveSelections["remote"])
        assertEquals(0, selectors.length())
        val before = applications
        center.remote.getJSONObject("agent_settings").put("android_capture", JSONObject().put("file_kb", 256).put("domains", org.json.JSONArray().put("example.com")))
        center.remote.put("patch_version", 400L)
        repository.syncConfiguration()
        assertEquals(256, capture.getInt("file_kb")); assertTrue(applications > before)
        assertFalse(capture.has("enabled")); assertFalse(capture.has("auto_upload"))
        val settled = applications
        center.remote.getJSONObject("agent_settings").getJSONObject("android_capture")
            .put("future_template_option", "preserved").put("enabled", true).put("auto_upload", true)
        center.remote.put("patch_version", 450L)
        assertFalse(repository.syncConfiguration())
        assertEquals(settled, applications)
        assertFalse(capture.has("enabled")); assertFalse(capture.has("auto_upload"))
        center.remote.getJSONObject("agent_settings").getJSONObject("android_capture").put("file_kb", 512)
        center.remote.put("patch_version", 500L); failCapture = true
        assertTrue(runCatching { repository.syncConfiguration() }.isFailure)
        assertEquals(256, capture.getInt("file_kb"))
        assertEquals("direct", liveSelections["remote"])
    }

    @Test fun captureTemplateSynchronizationCannotGrantSessionConsent() {
        val template = captureTemplate(CaptureConfig(enabled = true, domains = listOf("example.com"), autoUpload = true))
        assertFalse(template.has("enabled")); assertFalse(template.has("auto_upload"))
        assertEquals("example.com", template.getJSONArray("domains").getString(0))
    }

    @Test fun cachedDraftCannotCrossDeviceIdentity() {
        val store = Memory(); val center = Center(); val sync = ManagedConfigSync(store, center)
        sync.synchronize(enrollment, null)
        assertTrue(runCatching { sync.synchronize(enrollment.copy(hostId = "other"), null) }.isFailure)
    }
}
