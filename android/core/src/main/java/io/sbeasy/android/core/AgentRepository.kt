package io.sbeasy.android.core

import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONObject

class AgentRepository internal constructor(
    private val secureStore: SecureEnrollmentStore,
    private val configStore: AtomicConfigStore,
    private val client: ControlPlaneClient,
    private val installId: String,
) {
    private val syncMutex = Mutex()
    private val mutableState = MutableStateFlow(
        ControlPlaneSnapshot(
            enrollment = secureStore.load(),
            config = configStore.active(),
        ),
    )
    val state: StateFlow<ControlPlaneSnapshot> = mutableState.asStateFlow()
    private val routeTester = RouteTester()

    suspend fun enroll(rawUri: String, appVersion: String, coreVersion: String) = withContext(Dispatchers.IO) {
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

    suspend fun syncConfiguration(force: Boolean = false): Boolean = syncMutex.withLock {
        val enrollment = requireNotNull(mutableState.value.enrollment) { "设备尚未注册" }
        mutableState.value = mutableState.value.copy(syncPhase = SyncPhase.SYNCING, lastError = null)
        try {
            val active = configStore.active()
            when (val result = withContext(Dispatchers.IO) {
                client.fetchConfig(enrollment, active?.etag, force)
            }) {
                ConfigFetchResult.NotModified -> {
                    mutableState.value = mutableState.value.copy(
                        config = active,
                        syncPhase = SyncPhase.CURRENT,
                    )
                    false
                }
                is ConfigFetchResult.Updated -> {
                    require(result.config.etag.isNotBlank()) { "服务器配置缺少 ETag" }
                    configStore.saveCandidate(result.config)
                    val control = RuntimeBridge.control
                    if (control != null) {
                        control.applyConfiguration(result.config)
                    } else {
                        requireNotNull(RuntimeBridge.validator) { "sing-box 核心尚未初始化" }
                            .validate(result.config.content)
                    }
                    val promoted = configStore.promoteCandidate()
                    mutableState.value = mutableState.value.copy(
                        config = promoted,
                        syncPhase = SyncPhase.CURRENT,
                        lastError = null,
                    )
                    VpnRuntimeState.configurationChanged(promoted)
                    true
                }
            }
        } catch (error: Throwable) {
            mutableState.value = mutableState.value.copy(
                config = configStore.active(),
                syncPhase = SyncPhase.ERROR,
                lastError = friendly(error),
            )
            throw error
        }
    }

    suspend fun runControlCycle(appVersion: String, coreVersion: String) {
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

    suspend fun selectOutbound(groupTag: String, outboundTag: String) {
        requireNotNull(RuntimeBridge.control) { "VPN 未运行" }.selectOutbound(groupTag, outboundTag)
        RuntimeObservability.markSelection(groupTag, outboundTag)
    }

    suspend fun testGroup(groupTag: String): GroupTestResult {
        val before = RuntimeObservability.groups.value.find { it.tag == groupTag }
            ?: error("测速组 $groupTag 尚未就绪")
        val previousTimes = before.items.associate { it.tag to it.urlTestTime }
        val startedAt = System.currentTimeMillis()
        requireNotNull(RuntimeBridge.control) { "VPN 未运行" }.urlTest(groupTag)
        val updated = withTimeoutOrNull(45_000) {
            RuntimeObservability.groups.first { groups ->
                groups.find { it.tag == groupTag }?.items?.any { item ->
                    item.urlTestTime > (previousTimes[item.tag] ?: 0L)
                } == true
            }.find { it.tag == groupTag }
        } ?: error("节点测速超时，请检查当前网络后重试")
        // libbox publishes results incrementally. Allow the current batch to
        // settle briefly while the UI continues observing later updates.
        delay(750)
        val latest = RuntimeObservability.groups.value.find { it.tag == groupTag } ?: updated
        val enrollment = mutableState.value.enrollment
        if (enrollment != null) {
            withContext(Dispatchers.IO) {
                client.reportLatencies(
                    enrollment,
                    latest.items.associate { item ->
                        item.tag to item.urlTestDelay.takeIf { it > 0 }
                    },
                )
            }
        }
        return GroupTestResult(
            groupTag = groupTag,
            tested = latest.items.count { it.urlTestDelay > 0 },
            total = latest.items.size,
            elapsedMillis = System.currentTimeMillis() - startedAt,
        )
    }

    suspend fun testRoute(url: String): RouteTestResult = routeTester.test(url)

    suspend fun clearRuntimeLogs() {
        RuntimeBridge.control?.clearLogs()
        RuntimeObservability.clearLogs()
        ClientDiagnostics.clear()
    }

    fun forgetDevice() {
        check(VpnRuntimeState.state.value.phase == VpnPhase.DISCONNECTED ||
            VpnRuntimeState.state.value.phase == VpnPhase.ERROR) { "请先断开 VPN" }
        secureStore.clear()
        configStore.clear()
        mutableState.value = ControlPlaneSnapshot()
    }

    fun activeConfig(): ManagedConfig? = configStore.active()

    private fun friendly(error: Throwable): String =
        error.message?.takeIf { it.isNotBlank() } ?: error.javaClass.simpleName
}
