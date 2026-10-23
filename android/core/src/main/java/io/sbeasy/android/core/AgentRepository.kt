package io.sbeasy.android.core

import android.os.Build
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

class AgentRepository internal constructor(
    private val secureStore: EnrollmentStorage,
    private val managedConfigStore: ConfigurationStorage,
    private val client: AgentControlPlane,
    private val installId: String,
    private val managedRoutingStore: RoutingStorage,
    private val standaloneConfigStore: ConfigurationStorage,
    private val standaloneRoutingStore: RoutingStorage,
    private val subscriptionStore: SubscriptionStorage,
    private val subscriptionFetcher: SubscriptionSource = SubscriptionFetcher(),
) {
    private val syncMutex = Mutex()
    private val healthMutex = Mutex()
    private val mutableHealth = MutableStateFlow(HealthSnapshot())
    val health: StateFlow<HealthSnapshot> = mutableHealth.asStateFlow()
    @Volatile private var lastHealthPolicy: LocalRoutingPolicy? = null
    @Volatile private var lastHealthGeneration = -1L
    private var mode = subscriptionStore.mode()
    private val configStore get() = if (mode == ClientMode.STANDALONE) standaloneConfigStore else managedConfigStore
    private val routingStore get() = if (mode == ClientMode.STANDALONE) standaloneRoutingStore else managedRoutingStore
    private val initialEnrollment = if (mode == ClientMode.MANAGED) secureStore.load() else null
    private val mutableSubscriptions = MutableStateFlow(subscriptionStore.load())
    val subscriptions: StateFlow<List<LocalSubscription>> = mutableSubscriptions.asStateFlow()
    private val storedPolicy = routingStore.load()
    private var localPolicy = configStore.active()?.let { base ->
        LocalRouting.migrateProvisionedDefaults(base.content, storedPolicy ?: LocalRouting.defaults(base.content))
    } ?: storedPolicy
    private var policyPersisted = storedPolicy != null && storedPolicy == localPolicy
    private val mutableRouting = MutableStateFlow(
        configStore.active()?.let { base ->
            LocalRouting.render(base.content, requireNotNull(localPolicy), initialEnrollment?.server.orEmpty(), mode == ClientMode.MANAGED).snapshot
        } ?: LocalRoutingSnapshot(),
    )
    val routing: StateFlow<LocalRoutingSnapshot> = mutableRouting.asStateFlow()
    private val mutableState = MutableStateFlow(
        ControlPlaneSnapshot(
            mode = mode,
            enrollment = initialEnrollment,
            config = configStore.active()?.let { base ->
                base.copy(content = LocalRouting.render(base.content, requireNotNull(localPolicy), initialEnrollment?.server.orEmpty(), mode == ClientMode.MANAGED).content)
            },
        ),
    )
    val state: StateFlow<ControlPlaneSnapshot> = mutableState.asStateFlow()
    private val routeTester = RouteTester()

    suspend fun enroll(rawUri: String, appVersion: String, coreVersion: String, allowInsecureLocalHttp: Boolean = false) = withContext(Dispatchers.IO) {
        check(mode == ClientMode.MANAGED) { "请先切换到受管模式" }
        mutableState.value = mutableState.value.copy(syncPhase = SyncPhase.SYNCING, lastError = null)
        try {
            val enrollment = client.enroll(
                rawUri,
                JSONObject()
                    .put("platform", "android")
                    .put("app_version", appVersion)
                    .put("core_version", coreVersion)
                    .put("install_id", installId)
                    .put("model", "${Build.MANUFACTURER} ${Build.MODEL}".trim()),
                allowInsecureLocalHttp,
            )
            secureStore.save(enrollment)
            mutableState.value = mutableState.value.copy(enrollment = enrollment)
            syncConfiguration(force = true)
        } catch (error: Throwable) {
            mutableState.value = mutableState.value.copy(
                syncPhase = SyncPhase.ERROR,
                lastError = friendly(error),
            )
            throw error
        }
    }

    suspend fun allowManagedLocalHttp(allowed: Boolean) = syncMutex.withLock {
        check(mode == ClientMode.MANAGED) { "仅受管模式可以设置中心连接授权" }
        check(RuntimeBridge.control == null && VpnRuntimeState.state.value.phase in setOf(VpnPhase.DISCONNECTED, VpnPhase.ERROR)) { "请先停止 VPN 再更改中心连接授权" }
        val current = requireNotNull(mutableState.value.enrollment) { "设备尚未注册" }
        if (allowed) require(ManagedTransportPolicy.canAllowLocalHttp(current.server)) { "仅可允许使用内网或回环 IP 的局域网 HTTP 中心" }
        val next = current.copy(allowInsecureLocalHttp = allowed)
        withContext(Dispatchers.IO) { secureStore.save(next) }
        mutableState.value = mutableState.value.copy(enrollment = next, lastError = null)
    }

    suspend fun syncConfiguration(force: Boolean = false): Boolean {
        if (mode == ClientMode.STANDALONE) return refreshSubscriptions(force = force)
        return syncMutex.withLock {
            check(mode == ClientMode.MANAGED) { "客户端模式已变化，请重试" }
            val enrollment = requireNotNull(mutableState.value.enrollment) { "设备尚未注册" }
            mutableState.value = mutableState.value.copy(syncPhase = SyncPhase.SYNCING, lastError = null)
            try {
                val active = configStore.active()
                when (val result = withContext(Dispatchers.IO) {
                    client.fetchConfig(enrollment, active?.etag, force)
                }) {
                    ConfigFetchResult.NotModified -> {
                        if (active != null) {
                            val previous = localPolicy ?: LocalRouting.defaults(active.content)
                            val policy = LocalRouting.migrateProvisionedDefaults(active.content, previous)
                            if (policy != previous) updateLocalRoutingLocked(policy)
                            if (!policyPersisted) {
                                withContext(Dispatchers.IO) { routingStore.save(policy) }
                                policyPersisted = true
                            }
                            localPolicy = policy
                            publishRouting(active, policy)
                        }
                        mutableState.value = mutableState.value.copy(
                            config = active?.let { effectiveConfig(it) },
                            syncPhase = SyncPhase.CURRENT,
                        )
                        false
                    }
                    is ConfigFetchResult.Updated -> {
                        require(result.config.etag.isNotBlank()) { "服务器配置缺少 ETag" }
                        configStore.saveCandidate(result.config)
                        val previousPolicy = localPolicy
                        val policy = LocalRouting.migrateProvisionedDefaults(
                            result.config.content, previousPolicy ?: LocalRouting.defaults(result.config.content),
                        )
                        val effective = effectiveConfig(result.config, policy)
                        val control = RuntimeBridge.control
                        if (control != null) {
                            control.applyConfiguration(effective)
                        } else {
                            requireNotNull(RuntimeBridge.validator) { "sing-box 核心尚未初始化" }
                                .validate(effective.content)
                        }
                        val promoted = try {
                            if (!policyPersisted || policy != previousPolicy) {
                                withContext(Dispatchers.IO) { routingStore.save(policy) }
                            }
                            withContext(Dispatchers.IO) { configStore.promoteCandidate() }
                        } catch (error: Throwable) {
                            withContext(Dispatchers.IO) {
                                runCatching { if (previousPolicy == null) routingStore.clear() else routingStore.save(previousPolicy) }
                            }
                            active?.let { previous ->
                                if (control != null) runCatching { control.applyConfiguration(effectiveConfig(previous)) }
                            }
                            throw error
                        }
                        policyPersisted = true
                        localPolicy = policy
                        publishRouting(promoted, policy)
                        // Route observations describe one concrete generated config.
                        // Do not mix historical decisions from an older rule set with
                        // the newly applied policy.
                        RuntimeObservability.resetDomainRouteStats()
                        mutableState.value = mutableState.value.copy(
                            config = effectiveConfig(promoted, policy),
                            syncPhase = SyncPhase.CURRENT,
                            lastError = null,
                        )
                        VpnRuntimeState.configurationChanged(effective)
                        true
                    }
                }
            } catch (error: Throwable) {
                mutableState.value = mutableState.value.copy(
                    config = configStore.active()?.let { effectiveConfig(it) },
                    syncPhase = SyncPhase.ERROR,
                    lastError = friendly(error),
                )
                throw error
            }
        }
    }

    suspend fun runControlCycle(appVersion: String, coreVersion: String) {
        if (mode == ClientMode.STANDALONE) { refreshSubscriptions(); return }
        val enrollment = mutableState.value.enrollment ?: return
        runCatching { syncConfiguration() }
        runCatching {
            withContext(Dispatchers.IO) {
                client.reportStatus(
                    enrollment,
                    JSONObject()
                        .put("app_version", appVersion)
                        .put("singbox_version", coreVersion)
                        .put("singbox_running", VpnRuntimeState.state.value.phase == VpnPhase.CONNECTED)
                        .put("config_etag", configStore.active()?.etag ?: JSONObject.NULL)
                        .put("last_error", VpnRuntimeState.state.value.error ?: JSONObject.NULL),
                )
            }
        }
        val commands = runCatching { withContext(Dispatchers.IO) { client.commands(enrollment) } }
            .getOrDefault(emptyList())
        for (command in commands) {
            val result = runCatching {
                when (command.command) {
                    "reload" -> syncConfiguration(force = true)
                    "restart" -> requireNotNull(RuntimeBridge.control) { "VPN 未运行" }.restart()
                    else -> error("未知命令 ${command.command}")
                }
                "${command.command} completed"
            }
            withContext(Dispatchers.IO) {
                runCatching {
                    client.acknowledge(
                        enrollment,
                        command,
                        result.isSuccess,
                        result.getOrElse(::friendly),
                    )
                }
            }
        }
    }

    suspend fun reportTelemetry() {
        val enrollment = mutableState.value.enrollment ?: return
        val traffic = RuntimeObservability.traffic.value
        val logs = JSONArray()
        RuntimeObservability.logs.value.takeLast(200).forEach { logs.put(it.message.take(2_000)) }
        val domainStats = JSONArray()
        RuntimeObservability.domainRouteStats().forEach { stat ->
            val chain = JSONArray()
            stat.chain.forEach(chain::put)
            domainStats.put(
                JSONObject()
                    .put("domain", stat.domain)
                    .put("outbound", stat.outbound)
                    .put("outbound_type", stat.outboundType)
                    .put("rule", stat.rule)
                    .put("chain", chain)
                    .put("connection_count", stat.connectionCount)
                    .put("uplink_total", stat.uplinkTotal)
                    .put("downlink_total", stat.downlinkTotal)
                    .put("first_seen", stat.firstSeen)
                    .put("last_seen", stat.lastSeen),
            )
        }
        val body = JSONObject()
            .put("up", traffic.uplink)
            .put("down", traffic.downlink)
            .put("up_total", traffic.uplinkTotal)
            .put("down_total", traffic.downlinkTotal)
            .put("conn_count", traffic.connectionsIn + traffic.connectionsOut)
            .put("connections", JSONArray())
            .put("domain_stats", domainStats)
            .put("logs", logs)
        RuntimeObservability.persistDomainRouteStats()
        withContext(Dispatchers.IO) { client.reportTelemetry(enrollment, body) }
    }

    suspend fun uploadDiagnostics(appVersion: String, coreVersion: String): String {
        val enrollment = requireNotNull(mutableState.value.enrollment) { "设备尚未注册" }
        ClientDiagnostics.info("diagnostics", "manual diagnostic upload requested")
        val vpn = VpnRuntimeState.state.value
        val config = mutableState.value.config
        val logs = JSONArray()
        ClientDiagnostics.snapshotLines().forEach { line -> logs.put(line.take(4_000)) }
        val body = JSONObject()
            .put("reason", "manual")
            .put("app_version", appVersion)
            .put("core_version", coreVersion)
            .put(
                "device",
                JSONObject()
                    .put("manufacturer", Build.MANUFACTURER)
                    .put("model", Build.MODEL)
                    .put("sdk", Build.VERSION.SDK_INT)
                    .put("release", Build.VERSION.RELEASE),
            )
            .put(
                "vpn",
                JSONObject()
                    .put("phase", vpn.phase.name)
                    .put("detail", vpn.detail)
                    .put("started_at_ms", vpn.startedAtMillis ?: JSONObject.NULL)
                    .put("error", vpn.error ?: JSONObject.NULL),
            )
            .put("network", client.networkSnapshot())
            .put(
                "config",
                JSONObject()
                    .put("profile_id", config?.profileId ?: JSONObject.NULL)
                    .put("profile_name", config?.profileName ?: JSONObject.NULL)
                    .put("etag", config?.etag?.take(80) ?: JSONObject.NULL)
                    .put("rule_source", config?.ruleSource ?: JSONObject.NULL),
            )
            .put("runtime_log_count", RuntimeObservability.logs.value.size)
            .put("connection_count", RuntimeObservability.connections.value.size)
            .put("logs", logs)
        return try {
            val reportId = withContext(Dispatchers.IO) { client.uploadDiagnostics(enrollment, body) }
            ClientDiagnostics.info("diagnostics", "diagnostic upload completed report=$reportId")
            reportId
        } catch (error: Throwable) {
            ClientDiagnostics.error("diagnostics", "diagnostic upload failed", error)
            throw error
        }
    }

    suspend fun selectOutbound(groupTag: String, outboundTag: String) = syncMutex.withLock {
        val snapshot = mutableRouting.value
        val policy = snapshot.policy
        val id = snapshot.groupTags.entries.firstOrNull { it.value == groupTag }?.key
        if (policy != null && (id != null || groupTag == snapshot.defaultTag)) {
            require(snapshot.availableNodes.any { it.tag == outboundTag }) { "节点已失效，请重新选择" }
            val available = snapshot.availableNodes.filter { it.type != "automatic" && it.tag != "direct" }.map { it.tag }
            fun candidates(previous: List<String>, fixed: String) = previous.filter { it in available }.ifEmpty {
                if (fixed in available) listOf(fixed) else available.take(1)
            }
            val updated = if (id == null) policy.copy(defaultOutbound = outboundTag,
                defaultAutomaticCandidates = if (outboundTag == LocalRouting.AUTOMATIC) candidates(policy.defaultAutomaticCandidates, policy.defaultOutbound) else policy.defaultAutomaticCandidates) else policy.copy(
                groups = policy.groups.map { if (it.id == id) it.copy(outbound = outboundTag,
                    automaticCandidates = if (outboundTag == LocalRouting.AUTOMATIC) candidates(it.automaticCandidates, it.outbound) else it.automaticCandidates) else it },
            )
            updateLocalRoutingLocked(updated.copy(presetRevision = maxOf(1, updated.presetRevision),
                health = if (outboundTag == LocalRouting.AUTOMATIC) updated.health.copy(enabled = true) else updated.health))
        } else {
            requireNotNull(RuntimeBridge.control) { "VPN 未运行" }.selectOutbound(groupTag, outboundTag)
            RuntimeObservability.markSelection(groupTag, outboundTag)
        }
    }

    suspend fun updateLocalRouting(policy: LocalRoutingPolicy) = syncMutex.withLock {
        updateLocalRoutingLocked(policy.copy(presetRevision = maxOf(1, policy.presetRevision)))
    }

    private suspend fun updateLocalRoutingLocked(policy: LocalRoutingPolicy) {
        LocalRouting.validate(policy)
        val base = requireNotNull(configStore.active()) { "请先同步配置或导入订阅" }
        val previous = effectiveConfig(base)
        val rendered = effectiveConfig(base, policy)
        val control = RuntimeBridge.control
        withContext(Dispatchers.IO) {
            requireNotNull(RuntimeBridge.validator) { "sing-box 核心尚未初始化" }.validate(rendered.content)
        }
        val previousSnapshot = mutableRouting.value
        val selectionOnly = previousSnapshot.policy?.let { old ->
            old.groups.map { it.copy(outbound = "") } == policy.groups.map { it.copy(outbound = "") }
        } == true && LocalRouting.sameDnsConfiguration(previous.content, rendered.content) &&
            LocalRouting.sameSelectorCandidates(previous.content, rendered.content)
        val nextSnapshot = LocalRouting.render(base.content, policy, mutableState.value.enrollment?.server.orEmpty(), mode == ClientMode.MANAGED).snapshot
        val changedSelections = nextSnapshot.selections.filter { (tag, selection) ->
            previousSnapshot.selections[tag] != selection
        }
        try {
            if (control != null) {
                if (selectionOnly) changedSelections.forEach { (tag, selection) -> control.selectOutbound(tag, selection) }
                else control.applyConfiguration(rendered)
            }
            withContext(Dispatchers.IO) { routingStore.save(policy) }
        } catch (error: Throwable) {
            if (control != null) {
                if (selectionOnly) changedSelections.keys.forEach { tag ->
                    previousSnapshot.selections[tag]?.let { selection -> runCatching { control.selectOutbound(tag, selection) } }
                } else runCatching { control.applyConfiguration(previous) }
            }
            throw error
        }
        policyPersisted = true
        localPolicy = policy
        publishRouting(base, policy)
        mutableState.value = mutableState.value.copy(config = rendered, lastError = null)
        if (selectionOnly) changedSelections.forEach { (tag, selection) -> RuntimeObservability.markSelection(tag, selection) }
        RuntimeObservability.resetDomainRouteStats()
        VpnRuntimeState.configurationChanged(rendered)
    }


    fun invalidateHealth() { lastHealthGeneration = -1L }

    suspend fun runHealthCycle(force: Boolean = false): Boolean = healthMutex.withLock {
        val runtime = RuntimeBridge.control ?: return@withLock false
        if (VpnRuntimeState.state.value.phase != VpnPhase.CONNECTED) return@withLock false
        val snapshot = mutableRouting.value
        val policy = snapshot.policy ?: return@withLock false
        val now = System.currentTimeMillis()
        val generation = runtime.configurationGeneration
        val previousCheck = mutableHealth.value.checkedAtMillis
        if (!force && (!policy.health.enabled || (policy == lastHealthPolicy && generation == lastHealthGeneration &&
                now >= previousCheck && now - previousCheck < policy.health.intervalSeconds * 1000L))) return@withLock false
        val configContent = mutableState.value.config?.content ?: return@withLock false
        val groups = RuntimeObservability.groups.value.associate { it.tag to it.selected }
        val tags = (snapshot.selections.filterKeys { it !in snapshot.blockedGroups }.values + snapshot.automaticGroups.values.flatten())
            .filter { it != "direct" && it != LocalRouting.AUTOMATIC }.distinct()
        mutableHealth.value = mutableHealth.value.copy(checking = true)
        try {
            val semaphore = Semaphore(8)
            val measured = coroutineScope {
                tags.map { tag -> async {
                    semaphore.withPermit {
                        try { runtime.probeOutbound(tag, policy.health.probeUrl, policy.health.timeoutMillis) }
                        catch (cancelled: CancellationException) { throw cancelled }
                        catch (_: Exception) { NodeHealthResult(tag, null, "节点探测失败") }
                    }
                } }.awaitAll()
            }
            syncMutex.withLock applyHealth@ {
                if (mutableState.value.config?.content != configContent || mutableRouting.value.policy != policy ||
                    RuntimeBridge.control !== runtime || runtime.configurationGeneration != generation || VpnRuntimeState.state.value.phase != VpnPhase.CONNECTED) {
                    mutableHealth.value = mutableHealth.value.copy(checking = false)
                    return@applyHealth false
                }
                val selected = linkedMapOf<String, String>()
                val warnings = mutableListOf<String>()
                for ((groupTag, candidates) in snapshot.automaticGroups) {
                    val current = groups[groupTag] ?: mutableHealth.value.selected[groupTag] ?: snapshot.selections[groupTag]
                    val chosen = HealthSelection.choose(current, candidates, measured, policy.health)
                    if (chosen == null) {
                        warnings += "${groupName(snapshot, groupTag)}：全部候选节点探测失败，保留当前出口，不回退直连"
                    } else {
                        // Reapply even when observations agree: a restarted core may have restored
                        // its initial selector before the command monitor publishes its first snapshot.
                        try {
                            runtime.selectOutbound(groupTag, chosen)
                            RuntimeObservability.markSelection(groupTag, chosen)
                        } catch (cancelled: CancellationException) { throw cancelled }
                        catch (_: Exception) { warnings += "${groupName(snapshot, groupTag)}：切换失败，保留当前出口"; continue }
                        selected[groupTag] = chosen
                    }
                }
                val fixed = snapshot.selections.filterKeys { it !in snapshot.automaticGroups && it !in snapshot.blockedGroups }.values.toSet()
                measured.filter { it.tag in fixed && !it.healthy }.forEach { warnings += "固定节点「${it.tag}」探测失败，保持原出口" }
                RuntimeObservability.recordHealthResults(measured)
                mutableHealth.value = HealthSnapshot(false, System.currentTimeMillis(), measured, selected, warnings + snapshot.warnings)
                lastHealthPolicy = policy
                lastHealthGeneration = generation
                true
            }
        } finally {
            if (mutableHealth.value.checking) mutableHealth.value = mutableHealth.value.copy(checking = false)
        }
    }

    private fun groupName(snapshot: LocalRoutingSnapshot, tag: String): String =
        if (tag == snapshot.defaultTag) "默认代理" else snapshot.policy?.groups?.firstOrNull { snapshot.groupTags[it.id] == tag }?.name ?: "自动分组"

    suspend fun testGroup(groupTag: String): GroupTestResult = healthMutex.withLock {
        val before = RuntimeObservability.groups.value.find { it.tag == groupTag }
            ?: error("测速组尚未就绪")
        val runtime = requireNotNull(RuntimeBridge.control) { "VPN 未运行" }
        val generation = runtime.configurationGeneration
        val healthPolicy = mutableRouting.value.policy?.health ?: HealthPolicy()
        val targets = before.items.filter { it.type.lowercase() !in setOf("direct", "block", "dns", "selector", "urltest") }.map { it.tag }.distinct()
        require(targets.size <= 512) { "此组超过 512 个节点，请缩小自动候选池后测速" }
        val startedAt = System.currentTimeMillis()
        val semaphore = Semaphore(8)
        mutableHealth.value = mutableHealth.value.copy(checking = true)
        try {
            val results = coroutineScope { targets.map { tag -> async { semaphore.withPermit {
                runtime.probeOutbound(tag, healthPolicy.probeUrl, healthPolicy.timeoutMillis)
            } } }.awaitAll() }
            check(RuntimeBridge.control === runtime && runtime.configurationGeneration == generation) { "测速期间配置已变化，请重试" }
            RuntimeObservability.recordHealthResults(results)
            mutableHealth.value = mutableHealth.value.copy(checking = false, checkedAtMillis = System.currentTimeMillis(),
                results = mutableHealth.value.results.filter { it.tag !in targets } + results)
            mutableState.value.enrollment?.let { enrollment ->
                withContext(Dispatchers.IO) { runCatching { client.reportLatencies(enrollment, results.associate { it.tag to it.latencyMillis }) } }
            }
            GroupTestResult(groupTag, results.count { it.healthy }, results.size, System.currentTimeMillis() - startedAt)
        } finally {
            if (mutableHealth.value.checking) mutableHealth.value = mutableHealth.value.copy(checking = false)
        }
    }

    suspend fun updateRuntimeOverlay(requireRunning: Boolean = false, update: () -> Unit, rollback: () -> Unit) = syncMutex.withLock {
        val runtime = RuntimeBridge.control
        val config = mutableState.value.config
        if (requireRunning) check(runtime != null && config != null && VpnRuntimeState.state.value.phase == VpnPhase.CONNECTED) { "VPN 未运行" }
        update()
        if (runtime != null && config != null) {
            try { runtime.applyConfiguration(config) }
            catch (failure: Throwable) {
                if (RuntimeBridge.control === runtime && VpnRuntimeState.state.value.phase == VpnPhase.CONNECTED) {
                    rollback()
                    runCatching { runtime.applyConfiguration(config) }
                }
                throw failure
            }
        }
    }

    suspend fun saveCaptureConfiguration(config: CaptureConfig) = syncMutex.withLock {
        CaptureSession.requireEnabled()
        val next = config.validated()
        require(mode == ClientMode.MANAGED || !next.autoUpload) { "独立模式只保留本机文件，不支持上传中心" }
        withContext(Dispatchers.IO) { PacketCapture.validateFilter(next.bpf) }
        val previous = PacketCapture.config()
        withContext(Dispatchers.IO) { PacketCapture.save(next) }
        try { RuntimeBridge.control?.restart() }
        catch (error: Throwable) {
            withContext(Dispatchers.IO) { PacketCapture.save(previous) }
            runCatching { RuntimeBridge.control?.restart() }
            throw error
        }
    }

    suspend fun uploadCaptures(manual: Boolean = true) {
        val snapshot = mutableState.value
        if (snapshot.mode != ClientMode.MANAGED) {
            check(!manual) { "独立模式不会上传采集内容" }
            return
        }
        val enrollment = snapshot.enrollment ?: return
        PacketCapture.upload(enrollment, client, manual)
    }

    suspend fun testRoute(url: String): RouteTestResult = routeTester.test(url)

    suspend fun clearRuntimeLogs() {
        RuntimeBridge.control?.clearLogs()
        RuntimeObservability.clearLogs()
        ClientDiagnostics.clear()
    }

    suspend fun forgetDevice() = syncMutex.withLock {
        check(mode == ClientMode.MANAGED) { "请在订阅页删除本机订阅" }
        check(RuntimeBridge.control == null && VpnRuntimeState.state.value.phase in setOf(VpnPhase.DISCONNECTED, VpnPhase.ERROR)) { "请先停止 VPN" }
        PacketCapture.endSession()
        HttpDebug.release()
        secureStore.clear()
        configStore.clear()
        routingStore.clear()
        localPolicy = null
        policyPersisted = false
        mutableRouting.value = LocalRoutingSnapshot()
        AppTrafficStore.clear()
        RuntimeObservability.resetDomainRouteStats()
        mutableState.value = ControlPlaneSnapshot()
    }


    suspend fun switchMode(next: ClientMode) = syncMutex.withLock {
        if (next == mode) return@withLock
        check(RuntimeBridge.control == null && VpnRuntimeState.state.value.phase in setOf(VpnPhase.DISCONNECTED, VpnPhase.ERROR)) { "请先停止 VPN 再切换模式" }
        val enrollment = if (next == ClientMode.MANAGED) secureStore.load() else null
        val targetStore = if (next == ClientMode.STANDALONE) standaloneConfigStore else managedConfigStore
        val targetRouting = if (next == ClientMode.STANDALONE) standaloneRoutingStore else managedRoutingStore
        val base = targetStore.active()
        val persisted = targetRouting.load()
        val policy = persisted ?: base?.let { LocalRouting.defaults(it.content) }
        val rendered = base?.let { LocalRouting.render(it.content, requireNotNull(policy), enrollment?.server.orEmpty(), next == ClientMode.MANAGED) }
        withContext(Dispatchers.IO) { subscriptionStore.setMode(next) }
        PacketCapture.endSession()
        HttpDebug.release()
        mode = next
        localPolicy = policy
        policyPersisted = persisted != null
        mutableState.value = ControlPlaneSnapshot(mode = next, enrollment = enrollment, config = base?.copy(content = requireNotNull(rendered).content))
        mutableRouting.value = rendered?.snapshot ?: LocalRoutingSnapshot()
        // Prevent standalone connection metadata from being uploaded after returning to a center.
        mutableHealth.value = HealthSnapshot()
        lastHealthPolicy = null
        RuntimeObservability.resetRuntime()
        RuntimeObservability.clearLogs()
        ClientDiagnostics.clear(includeAdditionalLogs = true)
        RuntimeObservability.resetDomainRouteStats()
    }

    suspend fun saveSubscription(id: String?, name: String, source: String, remote: Boolean, intervalMinutes: Int, allowInsecure: Boolean): SubscriptionImport = syncMutex.withLock {
        require(name.isNotBlank() && name.length <= 80) { "订阅名称须为 1–80 个字符" }
        require(intervalMinutes == 0 || intervalMinutes in 15..10080) { "更新间隔须为 15–10080 分钟，0 表示关闭" }
        val previous = mutableSubscriptions.value
        require(id == null || previous.any { it.id == id }) { "订阅已被删除" }
        require(id != null || previous.size < 16) { "最多保存 16 个订阅" }
        val canonical = if (remote) SubscriptionParser.subscriptionUrl(source, allowInsecure) else source.trim()
        val download = withContext(Dispatchers.IO) {
            if (remote) safeDownload(canonical, allowInsecure) else SubscriptionFetcher.Download(canonical, SubscriptionQuota())
        }
        val imported = withContext(Dispatchers.Default) { SubscriptionParser.parse(download.content) }
        val now = System.currentTimeMillis()
        val record = LocalSubscription(id ?: java.util.UUID.randomUUID().toString(), name.trim(), canonical, remote,
            allowInsecure, if (remote) intervalMinutes else 0, imported.nodes.map { it.toString() }, download.quota,
            imported.issues, imported.format, now, now)
        val updated = if (id == null) previous + record else previous.map { if (it.id == id) record else it }
        applySubscriptions(updated)
        imported
    }

    suspend fun removeSubscription(id: String) = syncMutex.withLock {
        val next = mutableSubscriptions.value.filterNot { it.id == id }
        if (next.size == mutableSubscriptions.value.size) return@withLock
        if (next.isEmpty() && mode == ClientMode.STANDALONE) {
            check(VpnRuntimeState.state.value.phase in setOf(VpnPhase.DISCONNECTED, VpnPhase.ERROR)) { "请先断开 VPN 再删除最后一个订阅" }
        }
        applySubscriptions(next)
    }

    suspend fun refreshSubscriptions(force: Boolean = false, onlyId: String? = null): Boolean = syncMutex.withLock {
        val now = System.currentTimeMillis()
        val previous = mutableSubscriptions.value
        val eligible = previous.filter { (onlyId == null || it.id == onlyId) && it.remote && (force || it.due(now)) }
        if (eligible.isEmpty()) return@withLock false
        if (mode == ClientMode.STANDALONE) mutableState.value = mutableState.value.copy(syncPhase = SyncPhase.SYNCING, lastError = null)
        var updated = previous
        for (record in eligible) {
            val result = runCatching {
                val download = withContext(Dispatchers.IO) { safeDownload(record.source, record.allowInsecure) }
                val parsed = withContext(Dispatchers.Default) { SubscriptionParser.parse(download.content) }
                record.copy(nodes = parsed.nodes.map { it.toString() }, quota = download.quota, issues = parsed.issues,
                    format = parsed.format, lastSuccess = now, lastAttempt = now, error = null)
            }.getOrElse {
                if (it is CancellationException) throw it
                record.copy(lastAttempt = now, error = friendly(it))
            }
            updated = updated.map { if (it.id == result.id) result else it }
        }
        try {
            applySubscriptions(updated)
        } catch (error: Throwable) {
            // Invalid downloaded configs never replace last-good nodes, metadata or runtime.
            val failed = previous.map { if (it in eligible) it.copy(lastAttempt = now, error = if (error is IllegalArgumentException) friendly(error) else "订阅配置校验或应用失败，已保留原节点") else it }
            withContext(Dispatchers.IO) { subscriptionStore.save(failed) }
            mutableSubscriptions.value = failed
            if (mode == ClientMode.STANDALONE) mutableState.value = mutableState.value.copy(syncPhase = SyncPhase.ERROR, lastError = "订阅更新失败，已保留可用配置")
            throw error
        }
        val failure = updated.firstOrNull { it.error != null }?.error
        if (mode == ClientMode.STANDALONE) mutableState.value = mutableState.value.copy(syncPhase = if (failure == null) SyncPhase.CURRENT else SyncPhase.ERROR, lastError = failure)
        updated != previous
    }

    private fun safeDownload(source: String, allowInsecure: Boolean): SubscriptionFetcher.Download = try {
        subscriptionFetcher.fetch(source, allowInsecure)
    } catch (error: IllegalArgumentException) { throw error }
      catch (error: CancellationException) { throw error }
      catch (_: Exception) { throw IllegalStateException("订阅下载失败，请检查网络和订阅地址；原配置保持可用") }

    private suspend fun applySubscriptions(next: List<LocalSubscription>) = withContext(NonCancellable) {
        val previous = mutableSubscriptions.value
        val oldBase = standaloneConfigStore.active()
        val oldPolicy = standaloneRoutingStore.load()
        val nextBase = next.takeIf { it.isNotEmpty() }?.let(SubscriptionParser::baseConfig)
        val policy = oldPolicy ?: nextBase?.let { LocalRouting.defaults(it.content) }
        if (oldPolicy != null && nextBase != null) {
            val tags = LocalRouting.availableNodes(nextBase.content).map { it.tag }.toSet() + "direct"
            val pinned = (listOf(oldPolicy.defaultOutbound) + oldPolicy.groups.map { it.outbound }).filter { it != LocalRouting.AUTOMATIC }
            require(pinned.all { it in tags }) { "订阅已移除正在使用的固定出口；已保留原节点，请先在代理页改选出口后再更新或删除订阅" }
        }
        val effective = nextBase?.let { it.copy(content = LocalRouting.render(it.content, requireNotNull(policy), includeGeoRules = false).content) }
        val oldEffective = if (mode == ClientMode.STANDALONE) mutableState.value.config else null
        val runtime = if (mode == ClientMode.STANDALONE) RuntimeBridge.control else null
        try {
            if (effective != null && oldBase?.etag != nextBase.etag) {
                withContext(Dispatchers.IO) { requireNotNull(RuntimeBridge.validator) { "sing-box 核心尚未初始化" }.validate(effective.content) }
                runtime?.applyConfiguration(effective)
            }
            withContext(Dispatchers.IO) {
                subscriptionStore.save(next)
                if (nextBase != null) {
                    standaloneConfigStore.saveCandidate(nextBase)
                    standaloneConfigStore.promoteCandidate()
                    standaloneRoutingStore.save(requireNotNull(policy))
                } else {
                    standaloneConfigStore.clear()
                    standaloneRoutingStore.clear()
                }
            }
        } catch (error: Throwable) {
            withContext(Dispatchers.IO) {
                runCatching { subscriptionStore.save(previous) }
                runCatching {
                    if (oldBase == null) standaloneConfigStore.clear()
                    else { standaloneConfigStore.saveCandidate(oldBase); standaloneConfigStore.promoteCandidate() }
                    if (oldPolicy == null) standaloneRoutingStore.clear() else standaloneRoutingStore.save(oldPolicy)
                }
            }
            if (runtime != null && oldEffective != null) runCatching { runtime.applyConfiguration(oldEffective) }
            throw error
        }
        mutableSubscriptions.value = next
        if (mode == ClientMode.STANDALONE) {
            localPolicy = policy
            policyPersisted = policy != null
            mutableRouting.value = if (nextBase != null) LocalRouting.render(nextBase.content, requireNotNull(policy), includeGeoRules = false).snapshot else LocalRoutingSnapshot()
            mutableState.value = mutableState.value.copy(config = effective, syncPhase = SyncPhase.CURRENT, lastError = null)
            if (effective != null) VpnRuntimeState.configurationChanged(effective)
            if (oldBase?.etag != nextBase?.etag) RuntimeObservability.resetDomainRouteStats()
        }
    }

    suspend fun exportPreferences(): String = syncMutex.withLock {
        PreferencesPayload.encode(PortablePreferences(mutableSubscriptions.value,
            standaloneRoutingStore.load(), managedRoutingStore.load()))
    }

    suspend fun previewPreferences(payload: String): PreferencesPreview = syncMutex.withLock {
        requirePreferencesStopped()
        val imported = withContext(Dispatchers.Default) { PreferencesPayload.decode(payload) }
        val merged = imported.copy(
            standaloneRouting = PreferencesPayload.retainDeviceRules(imported.standaloneRouting, standaloneRoutingStore.load()),
            managedRouting = PreferencesPayload.retainDeviceRules(imported.managedRouting, managedRoutingStore.load()),
        )
        validatePreferences(merged)
        PreferencesPreview(merged, preferencesBaseline(), buildString {
            append("将以 ${merged.subscriptions.size} 个订阅、${merged.subscriptions.sumOf { it.nodes.size }} 个缓存节点替换本机订阅。")
            append("\n独立模式 ${merged.standaloneRouting?.groups?.size ?: 0} 个分组；受管模式 ${merged.managedRouting?.groups?.size ?: 0} 个分组。")
            append("\n导入一般域名、出口及健康偏好，保留本机应用规则。当前模式与中心注册不变。")
            append("\n中心令牌、WireGuard 密钥、设备绑定、采集授权与 CA 不在文件中。")
        })
    }

    suspend fun importPreferences(preview: PreferencesPreview) = syncMutex.withLock {
        withContext(NonCancellable) {
        requirePreferencesStopped()
        check(preview.baseline == preferencesBaseline()) { "预览后本机配置已变化，请重新预览；尚未覆盖任何内容" }
        validatePreferences(preview.preferences)
        val next = preview.preferences
        val oldSubscriptions = mutableSubscriptions.value
        val oldStandalone = standaloneRoutingStore.load()
        val oldManaged = managedRoutingStore.load()
        val oldBase = standaloneConfigStore.active()
        val nextBase = next.subscriptions.takeIf { it.isNotEmpty() }?.let(SubscriptionParser::baseConfig)
        val nextStandalone = next.standaloneRouting ?: nextBase?.let { LocalRouting.defaults(it.content).let { policy ->
            policy.copy(groups = policy.groups.map { it.copy(includeOfficialApp = false) })
        } }
        withContext(NonCancellable + Dispatchers.IO) {
            try {
                subscriptionStore.save(next.subscriptions)
                if (nextStandalone == null) standaloneRoutingStore.clear() else standaloneRoutingStore.save(nextStandalone)
                if (next.managedRouting == null) managedRoutingStore.clear() else managedRoutingStore.save(next.managedRouting)
                if (nextBase == null) standaloneConfigStore.clear()
                else { standaloneConfigStore.saveCandidate(nextBase); standaloneConfigStore.promoteCandidate() }
            } catch (failure: Throwable) {
                runCatching { subscriptionStore.save(oldSubscriptions) }
                runCatching { if (oldStandalone == null) standaloneRoutingStore.clear() else standaloneRoutingStore.save(oldStandalone) }
                runCatching { if (oldManaged == null) managedRoutingStore.clear() else managedRoutingStore.save(oldManaged) }
                runCatching {
                    if (oldBase == null) standaloneConfigStore.clear()
                    else { standaloneConfigStore.saveCandidate(oldBase); standaloneConfigStore.promoteCandidate() }
                }
                throw failure
            }
        }
        mutableSubscriptions.value = next.subscriptions
        localPolicy = if (mode == ClientMode.STANDALONE) nextStandalone else next.managedRouting
        policyPersisted = localPolicy != null
        val base = configStore.active()
        if (base != null) {
            val policy = localPolicy ?: LocalRouting.defaults(base.content)
            localPolicy = policy
            publishRouting(base, policy)
            mutableState.value = mutableState.value.copy(config = effectiveConfig(base, policy), syncPhase = SyncPhase.CURRENT, lastError = null)
        } else {
            mutableRouting.value = LocalRoutingSnapshot(policy = localPolicy)
            mutableState.value = mutableState.value.copy(config = null, syncPhase = SyncPhase.IDLE, lastError = null)
        }
        mutableHealth.value = HealthSnapshot()
        lastHealthPolicy = null
        RuntimeObservability.resetDomainRouteStats()
        }
    }

    private fun requirePreferencesStopped() {
        check(RuntimeBridge.control == null && VpnRuntimeState.state.value.phase in setOf(VpnPhase.DISCONNECTED, VpnPhase.ERROR)) {
            "请先停止 VPN 再预览或导入偏好"
        }
    }

    private fun preferencesBaseline(): String = JSONObject().put("mode", mode.name)
        .put("subscriptions", JSONArray().also { rows -> mutableSubscriptions.value.forEach { rows.put(it.json()) } })
        .put("standalone", standaloneRoutingStore.load()?.let(LocalRouting::encode))
        .put("managed", managedRoutingStore.load()?.let(LocalRouting::encode)).toString()

    private suspend fun validatePreferences(value: PortablePreferences) {
        suspend fun validate(base: ManagedConfig, policy: LocalRoutingPolicy, managed: Boolean) {
            LocalRouting.validate(policy)
            val available = LocalRouting.availableNodes(base.content).map { it.tag }.toSet() + "direct"
            val fixed = (listOf(policy.defaultOutbound) + policy.groups.map { it.outbound }).filter { it != LocalRouting.AUTOMATIC }
            require(fixed.all { it in available }) { "偏好中的固定出口与目标设备节点冲突，请先调整分组或订阅" }
            val candidates = (if (policy.defaultOutbound == LocalRouting.AUTOMATIC) policy.defaultAutomaticCandidates else emptyList()) +
                policy.groups.filter { it.outbound == LocalRouting.AUTOMATIC }.flatMap { it.automaticCandidates }
            require(candidates.all { it in available && it != "direct" }) { "自动分组候选节点与目标设备冲突" }
            val config = LocalRouting.render(base.content, policy, if (managed) secureStore.load()?.server.orEmpty() else "", managed)
            withContext(Dispatchers.IO) { requireNotNull(RuntimeBridge.validator) { "sing-box 核心尚未初始化" }.validate(config.content) }
        }
        if (value.subscriptions.isNotEmpty()) {
            val base = SubscriptionParser.baseConfig(value.subscriptions)
            validate(base, value.standaloneRouting ?: LocalRouting.defaults(base.content), false)
        }
        value.managedRouting?.let { policy -> managedConfigStore.active()?.let { validate(it, policy, true) } }
    }

    fun activeConfig(): ManagedConfig? = mutableState.value.config

    private fun effectiveConfig(base: ManagedConfig, policy: LocalRoutingPolicy? = localPolicy): ManagedConfig =
        base.copy(content = LocalRouting.render(
            base.content,
            policy ?: LocalRouting.defaults(base.content),
            mutableState.value.enrollment?.server.orEmpty(),
            mode == ClientMode.MANAGED,
        ).content)

    private fun publishRouting(base: ManagedConfig, policy: LocalRoutingPolicy) {
        mutableRouting.value = LocalRouting.render(base.content, policy, mutableState.value.enrollment?.server.orEmpty(), mode == ClientMode.MANAGED).snapshot
    }

    private fun friendly(error: Throwable): String =
        error.message?.takeIf { it.isNotBlank() } ?: error.javaClass.simpleName
}
