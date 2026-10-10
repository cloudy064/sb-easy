package io.sbeasy.android.core

data class TrafficExit(
    val route: TrafficRoute,
    val outbound: String,
    val type: String,
    val chain: List<String>,
    val legacy: Boolean,
)

data class TrafficExitStat(val exit: TrafficExit, val uploaded: Long, val downloaded: Long)
data class HostTrafficStat(val host: String, val uploaded: Long, val downloaded: Long, val exits: List<TrafficExitStat>)

/** Input is already scoped to an app or registrable domain; never join unrelated legacy app totals. */
fun trafficHosts(details: List<TrafficDetailStat>): List<HostTrafficStat> = details.groupBy { it.key.host }.map { (host, rows) ->
    val exits = rows.groupBy { TrafficExit(it.key.route, it.key.outbound, it.key.outboundType, it.key.chain, it.key.legacy) }
        .map { (exit, values) -> TrafficExitStat(exit, values.sumOf { it.uploaded }, values.sumOf { it.downloaded }) }
        .sortedByDescending { it.uploaded + it.downloaded }
    HostTrafficStat(host, rows.sumOf { it.uploaded }, rows.sumOf { it.downloaded }, exits)
}.sortedByDescending { it.uploaded + it.downloaded }
