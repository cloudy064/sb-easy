package io.sbeasy.android.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object RuntimeObservability {
    private data class DomainRouteKey(
        val domain: String,
        val outbound: String,
        val outboundType: String,
        val rule: String,
        val chain: List<String>,
    )

    private data class MutableDomainRouteStat(
        var connectionCount: Long,
        var uplinkTotal: Long,
        var downlinkTotal: Long,
        val firstSeen: Long,
        var lastSeen: Long,
    )

    private data class ActiveConnection(
        var key: DomainRouteKey,
        var uplinkTotal: Long,
        var downlinkTotal: Long,
    )

    private val mutableTraffic = MutableStateFlow(TrafficSnapshot())
    private val mutableGroups = MutableStateFlow<List<ProxyGroupSnapshot>>(emptyList())
    private val mutableConnections = MutableStateFlow<List<ConnectionSnapshot>>(emptyList())
    private val mutableLogs = MutableStateFlow<List<RuntimeLog>>(emptyList())
    private val routeStatsLock = Any()
    private val routeStats = linkedMapOf<DomainRouteKey, MutableDomainRouteStat>()
    private val activeConnections = mutableMapOf<String, ActiveConnection>()

    val traffic: StateFlow<TrafficSnapshot> = mutableTraffic.asStateFlow()
    val groups: StateFlow<List<ProxyGroupSnapshot>> = mutableGroups.asStateFlow()
    val connections: StateFlow<List<ConnectionSnapshot>> = mutableConnections.asStateFlow()
    val logs: StateFlow<List<RuntimeLog>> = mutableLogs.asStateFlow()

    fun updateTraffic(value: TrafficSnapshot) {
        mutableTraffic.value = value
    }

    fun updateGroups(value: List<ProxyGroupSnapshot>) {
        mutableGroups.value = value
    }

    fun markSelection(groupTag: String, outboundTag: String) {
        mutableGroups.value = mutableGroups.value.map { group ->
            if (group.tag == groupTag) group.copy(selected = outboundTag) else group
        }
    }

    fun updateConnections(value: List<ConnectionSnapshot>) {
        mutableConnections.value = value.sortedByDescending { it.createdAt }.take(300)
    }

    fun recordConnectionOpened(id: String, value: ConnectionSnapshot) {
        val connectionId = id.ifBlank { value.id }
        if (connectionId.isBlank()) return
        val key = routeKey(value)
        val now = eventTime(value.createdAt)
        synchronized(routeStatsLock) {
            if (activeConnections.containsKey(connectionId)) return
            val uplink = value.uplinkTotal.coerceAtLeast(0)
            val downlink = value.downlinkTotal.coerceAtLeast(0)
            updateRouteStat(key, 1, uplink, downlink, now)
            activeConnections[connectionId] = ActiveConnection(key, uplink, downlink)
        }
    }

    fun recordConnectionTraffic(id: String, uplinkDelta: Long, downlinkDelta: Long) {
        if (id.isBlank()) return
        synchronized(routeStatsLock) {
            val active = activeConnections[id] ?: return
            val uplink = uplinkDelta.coerceAtLeast(0)
            val downlink = downlinkDelta.coerceAtLeast(0)
            active.uplinkTotal += uplink
            active.downlinkTotal += downlink
            updateRouteStat(active.key, 0, uplink, downlink, System.currentTimeMillis())
        }
    }

    fun recordConnectionClosed(id: String, value: ConnectionSnapshot?) {
        if (id.isBlank()) return
        synchronized(routeStatsLock) {
            val active = activeConnections.remove(id)
            if (active == null) {
                if (value != null) recordClosedWithoutOpen(value)
                return
            }
            val closedKey = value?.let(::routeKey) ?: active.key
            val closedUplink = value?.uplinkTotal?.coerceAtLeast(active.uplinkTotal) ?: active.uplinkTotal
            val closedDownlink = value?.downlinkTotal?.coerceAtLeast(active.downlinkTotal) ?: active.downlinkTotal
            val now = eventTime(value?.closedAt ?: 0L)
            if (closedKey != active.key) {
                subtractRouteStat(active.key, active.uplinkTotal, active.downlinkTotal)
                updateRouteStat(closedKey, 1, closedUplink, closedDownlink, now)
            } else {
                updateRouteStat(
                    active.key,
                    0,
                    closedUplink - active.uplinkTotal,
                    closedDownlink - active.downlinkTotal,
                    now,
                )
            }
        }
    }

    fun domainRouteStats(limit: Int = 500): List<DomainRouteStat> = synchronized(routeStatsLock) {
        routeStats.entries
            .sortedWith(
                compareByDescending<Map.Entry<DomainRouteKey, MutableDomainRouteStat>> { it.value.connectionCount }
                    .thenByDescending { it.value.downlinkTotal + it.value.uplinkTotal }
                    .thenBy { it.key.domain },
            )
            .take(limit.coerceIn(1, MAX_ROUTE_STATS))
            .map { (key, value) ->
                DomainRouteStat(
                    domain = key.domain,
                    outbound = key.outbound,
                    outboundType = key.outboundType,
                    rule = key.rule,
                    chain = key.chain,
                    connectionCount = value.connectionCount,
                    uplinkTotal = value.uplinkTotal,
                    downlinkTotal = value.downlinkTotal,
                    firstSeen = value.firstSeen,
                    lastSeen = value.lastSeen,
                )
            }
    }

    fun resetDomainRouteStats() = synchronized(routeStatsLock) {
        routeStats.clear()
        activeConnections.clear()
    }

    fun resetConnectionAccounting() {
        mutableConnections.value = emptyList()
        synchronized(routeStatsLock) { activeConnections.clear() }
    }

    fun appendLogs(value: List<RuntimeLog>) {
        if (value.isEmpty()) return
        mutableLogs.value = (mutableLogs.value + value).takeLast(800)
        ClientDiagnostics.appendLibbox(value)
    }

    fun clearLogs() {
        mutableLogs.value = emptyList()
    }

    fun resetRuntime() {
        mutableTraffic.value = TrafficSnapshot()
        mutableGroups.value = emptyList()
        resetConnectionAccounting()
    }

    private fun recordClosedWithoutOpen(value: ConnectionSnapshot) {
        val now = eventTime(value.closedAt)
        updateRouteStat(
            routeKey(value),
            1,
            value.uplinkTotal.coerceAtLeast(0),
            value.downlinkTotal.coerceAtLeast(0),
            now,
        )
    }

    private fun updateRouteStat(
        key: DomainRouteKey,
        connectionDelta: Long,
        uplinkDelta: Long,
        downlinkDelta: Long,
        at: Long,
    ) {
        val stat = routeStats[key]
        if (stat == null) {
            if (routeStats.size >= MAX_ROUTE_STATS) {
                routeStats.minByOrNull { it.value.lastSeen }?.key?.let(routeStats::remove)
            }
            routeStats[key] = MutableDomainRouteStat(
                connectionCount = connectionDelta.coerceAtLeast(0),
                uplinkTotal = uplinkDelta.coerceAtLeast(0),
                downlinkTotal = downlinkDelta.coerceAtLeast(0),
                firstSeen = at,
                lastSeen = at,
            )
            return
        }
        stat.connectionCount += connectionDelta.coerceAtLeast(0)
        stat.uplinkTotal += uplinkDelta.coerceAtLeast(0)
        stat.downlinkTotal += downlinkDelta.coerceAtLeast(0)
        stat.lastSeen = maxOf(stat.lastSeen, at)
    }

    private fun subtractRouteStat(key: DomainRouteKey, uplink: Long, downlink: Long) {
        val stat = routeStats[key] ?: return
        stat.connectionCount = (stat.connectionCount - 1).coerceAtLeast(0)
        stat.uplinkTotal = (stat.uplinkTotal - uplink).coerceAtLeast(0)
        stat.downlinkTotal = (stat.downlinkTotal - downlink).coerceAtLeast(0)
        if (stat.connectionCount == 0L && stat.uplinkTotal == 0L && stat.downlinkTotal == 0L) {
            routeStats.remove(key)
        }
    }

    private fun routeKey(value: ConnectionSnapshot): DomainRouteKey = DomainRouteKey(
        domain = observedDomain(value),
        outbound = value.outbound.trim().take(256),
        outboundType = value.outboundType.trim().take(80),
        rule = value.rule.trim().take(512),
        chain = value.chain.map(String::trim).filter(String::isNotEmpty).take(16).map { it.take(256) },
    )

    private fun observedDomain(value: ConnectionSnapshot): String {
        val reported = value.domain.trim().trimEnd('.').lowercase()
        if (reported.isNotEmpty()) return reported.take(512)
        val destination = value.destination.trim()
        val host = when {
            destination.startsWith('[') && destination.contains(']') -> destination.substring(1, destination.indexOf(']'))
            destination.count { it == ':' } == 1 -> destination.substringBeforeLast(':')
            else -> destination
        }
        return host.trim().trimEnd('.').lowercase().ifEmpty { "unknown" }.take(512)
    }

    private fun eventTime(value: Long): Long = value.takeIf { it > 0 } ?: System.currentTimeMillis()

    private const val MAX_ROUTE_STATS = 1_000
}

interface ConfigValidator {
    fun validate(content: String)
}

interface RuntimeControl {
    suspend fun applyConfiguration(config: ManagedConfig)
    suspend fun restart()
    suspend fun selectOutbound(groupTag: String, outboundTag: String)
    suspend fun urlTest(groupTag: String)
    suspend fun clearLogs()
}

object RuntimeBridge {
    @Volatile
    var validator: ConfigValidator? = null

    @Volatile
    var control: RuntimeControl? = null
}
