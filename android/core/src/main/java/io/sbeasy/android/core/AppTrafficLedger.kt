package io.sbeasy.android.core

import org.json.JSONArray
import org.json.JSONObject

data class AppTrafficStat(
    val key: String,
    val uid: Int?,
    val packages: List<String>,
    val uploaded: Long = 0,
    val downloaded: Long = 0,
)

data class DomainTrafficStat(val domain: String, val uploaded: Long = 0, val downloaded: Long = 0)

enum class TrafficRoute { DIRECT, PROXY, BLOCK, UNKNOWN }

data class TrafficDetailKey(
    val appKey: String,
    val domain: String,
    val host: String,
    val route: TrafficRoute,
    val outbound: String,
    val outboundType: String,
    // libbox provides the concrete exit first, followed by its selector ancestors.
    val chain: List<String> = emptyList(),
    val legacy: Boolean = false,
)

data class TrafficDetailStat(val key: TrafficDetailKey, val uploaded: Long = 0, val downloaded: Long = 0)

data class TrafficStatisticsSnapshot(
    val apps: List<AppTrafficStat> = emptyList(),
    val domains: List<DomainTrafficStat> = emptyList(),
    val details: List<TrafficDetailStat> = emptyList(),
)

/** One ledger per embedded-core lifetime; totals alone survive process restarts. */
class AppTrafficLedger(private val maxDetailRows: Int = 20_000) {
    private data class Checkpoint(val app: AppTrafficStat, val detail: TrafficDetailKey, val up: Long, val down: Long, val closedAt: Long)
    private val totals = linkedMapOf<String, AppTrafficStat>()
    private val domains = linkedMapOf<String, DomainTrafficStat>()
    private val details = linkedMapOf<TrafficDetailKey, TrafficDetailStat>()
    private val checkpoints = mutableMapOf<String, Checkpoint>()
    private var clearedAtMillis = 0L

    fun record(value: ConnectionSnapshot) {
        if (value.id.isBlank()) return
        val previous = checkpoints[value.id]
        val packages = value.appPackages.filter { it.isNotBlank() }.distinct().sorted()
        val uid = value.appUid?.takeIf { it >= 0 }
        // Preserve original attribution when final/replayed snapshots omit metadata.
        val appKey = previous?.app?.key ?: "${uid ?: -1}:${packages.joinToString(",")}"
        val identity = previous?.app ?: AppTrafficStat(appKey, uid, packages)
        val total = totals[appKey] ?: identity
        val up = value.uplinkTotal.coerceAtLeast(previous?.up ?: 0)
        val down = value.downlinkTotal.coerceAtLeast(previous?.down ?: 0)
        // An old connection first replayed after clear has no known baseline. Adopt
        // its current counters without resurrecting pre-clear history.
        val baselineOnly = previous == null && clearedAtMillis > 0 && value.createdAt <= clearedAtMillis
        val deltaUp = if (baselineOnly) 0 else up - (previous?.up ?: 0)
        val deltaDown = if (baselineOnly) 0 else down - (previous?.down ?: 0)
        val detail = previous?.detail ?: detailKey(appKey, value).let {
            if (it in details || details.size < maxDetailRows) it else overflowKey()
        }
        checkpoints[value.id] = Checkpoint(identity, detail, up, down, maxOf(value.closedAt, previous?.closedAt ?: 0))
        if (deltaUp == 0L && deltaDown == 0L) return
        totals[appKey] = total.copy(uploaded = total.uploaded + deltaUp, downloaded = total.downloaded + deltaDown)
        addDetail(detail, deltaUp, deltaDown)
    }

    private fun detailKey(appKey: String, value: ConnectionSnapshot): TrafficDetailKey {
        val host = TrafficDomain.host(value.domain, value.destination)
        val type = value.outboundType.trim()
        val route = when (type) {
            "direct" -> TrafficRoute.DIRECT
            "block" -> TrafficRoute.BLOCK
            "", "selector", "urltest", "dns" -> TrafficRoute.UNKNOWN
            else -> TrafficRoute.PROXY
        }
        return TrafficDetailKey(appKey, TrafficDomain.registrable(host), host, route,
            value.outbound.trim(), type, value.chain.filter { it.isNotBlank() })
    }

    private fun addDetail(key: TrafficDetailKey, up: Long, down: Long) {
        val row = details[key] ?: TrafficDetailStat(key)
        details[key] = row.copy(uploaded = row.uploaded + up, downloaded = row.downloaded + down)
        val domain = domains[key.domain] ?: DomainTrafficStat(key.domain)
        domains[key.domain] = domain.copy(uploaded = domain.uploaded + up, downloaded = domain.downloaded + down)
    }

    fun prune() {
        // libbox replays up to 1,000 closed connections on stream reconnect.
        checkpoints.entries.filter { it.value.closedAt > 0 }
            .sortedByDescending { it.value.closedAt }.drop(2_000)
            .forEach { checkpoints.remove(it.key) }
    }

    fun clearStatistics(nowMillis: Long = System.currentTimeMillis()) {
        totals.clear()
        domains.clear()
        details.clear()
        clearedAtMillis = nowMillis
        // Keep live/recent connection baselines and immutable app identity.
    }

    fun newCore() {
        checkpoints.clear()
        clearedAtMillis = 0L
    }
    fun snapshot(): List<AppTrafficStat> = totals.values.sortedByDescending { it.uploaded + it.downloaded }
    fun domainSnapshot(): List<DomainTrafficStat> = domains.values.sortedByDescending { it.uploaded + it.downloaded }
    fun detailSnapshot(): List<TrafficDetailStat> = details.values.sortedByDescending { it.uploaded + it.downloaded }
    fun statistics() = TrafficStatisticsSnapshot(snapshot(), domainSnapshot(), detailSnapshot())

    fun encode(): String = JSONObject().put("version", 3).put("apps", encodeApps()).put("details", JSONArray().apply {
        details.values.forEach { stat ->
            val key = stat.key
            put(JSONObject().put("app", key.appKey).put("domain", key.domain).put("host", key.host)
                .put("route", key.route.name).put("outbound", key.outbound).put("type", key.outboundType)
                .put("chain", JSONArray(key.chain)).put("legacy", key.legacy)
                .put("uploaded", stat.uploaded).put("downloaded", stat.downloaded))
        }
    }).toString()

    private fun encodeApps(): JSONArray = JSONArray().apply {
        totals.values.forEach { stat ->
            put(JSONObject().put("key", stat.key).put("uid", stat.uid ?: -1)
                .put("packages", JSONArray(stat.packages))
                .put("uploaded", stat.uploaded).put("downloaded", stat.downloaded))
        }
    }

    fun restore(payload: String) {
        // 1.2.4 stored app totals only; 1.2.5 stored independent full-host totals.
        val root = if (payload.trimStart().startsWith("[")) null else JSONObject(payload)
        val version = root?.getInt("version") ?: 1
        require(version in 1..3) { "Unsupported traffic data version" }
        val rows = root?.getJSONArray("apps") ?: JSONArray(payload)
        val restored = linkedMapOf<String, AppTrafficStat>()
        for (index in 0 until rows.length()) {
            val row = rows.getJSONObject(index)
            val stat = AppTrafficStat(row.getString("key"), row.getInt("uid").takeIf { it >= 0 },
                row.getJSONArray("packages").strings(), row.bytes("uploaded"), row.bytes("downloaded"))
            restored[stat.key] = stat
        }
        val restoredDetails = mutableListOf<TrafficDetailStat>()
        val detailRows = if (version == 3) root!!.getJSONArray("details") else root?.optJSONArray("domains") ?: JSONArray()
        for (index in 0 until detailRows.length()) {
            val row = detailRows.getJSONObject(index)
            val key = if (version == 3) {
                TrafficDetailKey(row.getString("app"), row.getString("domain"), row.getString("host"),
                    TrafficRoute.valueOf(row.getString("route")), row.getString("outbound"), row.getString("type"),
                    row.getJSONArray("chain").strings(), row.optBoolean("legacy"))
            } else {
                // Preserve the known host, but do not fabricate its application or historical exit.
                val host = when (val old = row.getString("domain")) {
                    UNKNOWN_DOMAIN -> UNKNOWN_HOST
                    OTHER_DOMAINS -> OTHER_HOST
                    else -> TrafficDomain.host(old)
                }
                TrafficDetailKey(LEGACY_APP, TrafficDomain.registrable(host), host, TrafficRoute.UNKNOWN, "", "", legacy = true)
            }
            restoredDetails += TrafficDetailStat(key, row.bytes("uploaded"), row.bytes("downloaded"))
        }
        totals.clear()
        totals.putAll(restored)
        domains.clear()
        details.clear()
        restoredDetails.forEach { addDetail(it.key, it.uploaded, it.downloaded) }
        newCore()
    }

    private fun JSONArray.strings(): List<String> = (0 until length()).map { getString(it) }
    private fun JSONObject.bytes(name: String) = getLong(name).coerceAtLeast(0)

    companion object {
        const val UNKNOWN_DOMAIN = "__unknown__"
        const val IP_DOMAIN = "__ip__"
        const val OTHER_DOMAINS = "__other__"
        const val UNKNOWN_HOST = "__unknown_host__"
        const val OTHER_HOST = "__other_hosts__"
        const val LEGACY_APP = "__legacy__"
        private fun overflowKey() = TrafficDetailKey("__overflow__", OTHER_DOMAINS, OTHER_HOST, TrafficRoute.UNKNOWN, "", "")
    }
}
