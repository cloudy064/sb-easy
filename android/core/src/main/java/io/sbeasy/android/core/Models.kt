package io.sbeasy.android.core

data class Enrollment(
    val server: String,
    val hostId: String,
    val hostName: String,
    val agentToken: String,
    val profileId: String,
    val profileName: String,
)

data class ManagedConfig(
    val content: String,
    val etag: String,
    val ruleSource: String,
    val profileId: String,
    val profileName: String,
    val syncedAtMillis: Long,
)

enum class SyncPhase { IDLE, SYNCING, CURRENT, ERROR }

data class ControlPlaneSnapshot(
    val enrollment: Enrollment? = null,
    val config: ManagedConfig? = null,
    val syncPhase: SyncPhase = SyncPhase.IDLE,
    val lastError: String? = null,
)

data class AgentCommand(
    val id: String,
    val command: String,
)

data class TrafficSnapshot(
    val uplink: Long = 0,
    val downlink: Long = 0,
    val uplinkTotal: Long = 0,
    val downlinkTotal: Long = 0,
    val connectionsIn: Int = 0,
    val connectionsOut: Int = 0,
    val memory: Long = 0,
    val goroutines: Int = 0,
)

data class ProxyItemSnapshot(
    val tag: String,
    val type: String,
    val urlTestTime: Long,
    val urlTestDelay: Int,
)

data class ProxyGroupSnapshot(
    val tag: String,
    val type: String,
    val selectable: Boolean,
    val selected: String,
    val items: List<ProxyItemSnapshot>,
)

data class ConnectionSnapshot(
    val id: String,
    val network: String,
    val source: String,
    val destination: String,
    val domain: String,
    val protocol: String,
    val createdAt: Long,
    val closedAt: Long,
    val uplink: Long,
    val downlink: Long,
    val uplinkTotal: Long,
    val downlinkTotal: Long,
    val rule: String,
    val outbound: String,
    val outboundType: String,
    val chain: List<String>,
)

data class RuntimeLog(
    val level: Int,
    val message: String,
    val timestampMillis: Long = System.currentTimeMillis(),
)

enum class RouteDecision { PROXY, DIRECT, BLOCK, UNKNOWN }

data class RouteTestResult(
    val url: String,
    val decision: RouteDecision,
    val outbound: String,
    val rule: String,
    val chain: List<String>,
    val latencyMillis: Long,
    val httpStatus: Int?,
    val error: String?,
)

data class ConfigSummary(
    val inboundTypes: List<String>,
    val dnsServers: Int,
    val routeRules: List<String>,
    val routeFinal: String,
    val outboundTags: List<String>,
    val sanitizedJson: String,
)
