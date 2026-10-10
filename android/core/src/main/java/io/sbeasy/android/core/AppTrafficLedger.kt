package io.sbeasy.android.core

import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

data class AppTrafficStat(
    val key: String,
    val uid: Int?,
    val packages: List<String>,
    val uploaded: Long = 0,
    val downloaded: Long = 0,
)

data class DomainTrafficStat(val domain: String, val uploaded: Long = 0, val downloaded: Long = 0)

/** One ledger per embedded-core lifetime; totals alone survive process restarts. */
class AppTrafficLedger {
    private data class Checkpoint(val key: String, val domain: String, val up: Long, val down: Long, val closedAt: Long)
    private val totals = linkedMapOf<String, AppTrafficStat>()
    private val domains = linkedMapOf<String, DomainTrafficStat>()
    private val checkpoints = mutableMapOf<String, Checkpoint>()

    fun record(value: ConnectionSnapshot) {
        if (value.id.isBlank()) return
        val previous = checkpoints[value.id]
        val packages = value.appPackages.filter { it.isNotBlank() }.distinct().sorted()
        val uid = value.appUid?.takeIf { it >= 0 }
        // Preserve initial attribution across partial closing/replayed snapshots.
        val key = previous?.key ?: "${uid ?: -1}:${packages.joinToString(",")}"
        val total = totals[key] ?: AppTrafficStat(key, uid, packages)
        val up = value.uplinkTotal.coerceAtLeast(previous?.up ?: 0)
        val down = value.downlinkTotal.coerceAtLeast(previous?.down ?: 0)
        totals[key] = total.copy(
            uploaded = total.uploaded + up - (previous?.up ?: 0),
            downloaded = total.downloaded + down - (previous?.down ?: 0),
        )
        val candidate = value.domain.trim().trimEnd('.').lowercase(Locale.ROOT).ifBlank { UNKNOWN_DOMAIN }
        val domain = previous?.domain ?: if (candidate in domains || domains.size < MAX_DOMAINS || candidate == UNKNOWN_DOMAIN) candidate else OTHER_DOMAINS
        val domainTotal = domains[domain] ?: DomainTrafficStat(domain)
        domains[domain] = domainTotal.copy(
            uploaded = domainTotal.uploaded + up - (previous?.up ?: 0),
            downloaded = domainTotal.downloaded + down - (previous?.down ?: 0),
        )
        checkpoints[value.id] = Checkpoint(key, domain, up, down, maxOf(value.closedAt, previous?.closedAt ?: 0))
    }

    fun prune() {
        // libbox replays up to 1,000 closed connections on stream reconnect.
        checkpoints.entries.filter { it.value.closedAt > 0 }
            .sortedByDescending { it.value.closedAt }.drop(2_000)
            .forEach { checkpoints.remove(it.key) }
    }

    fun newCore() = checkpoints.clear()

    fun snapshot(): List<AppTrafficStat> = totals.values.sortedByDescending { it.uploaded + it.downloaded }

    fun domainSnapshot(): List<DomainTrafficStat> = domains.values.sortedByDescending { it.uploaded + it.downloaded }

    fun encode(): String = JSONObject().put("version", 2).put("apps", encodeApps()).put("domains", JSONArray().apply {
        domains.values.forEach { stat ->
            put(JSONObject().put("domain", stat.domain).put("uploaded", stat.uploaded).put("downloaded", stat.downloaded))
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
        // 1.2.4 persisted a bare application array; migrate without inventing domain history.
        val root = if (payload.trimStart().startsWith("[")) null else JSONObject(payload)
        if (root != null) require(root.getInt("version") == 2) { "Unsupported traffic data version" }
        val rows = root?.getJSONArray("apps") ?: JSONArray(payload)
        val domainRows = root?.optJSONArray("domains") ?: JSONArray()
        val restoredDomains = linkedMapOf<String, DomainTrafficStat>()
        for (index in 0 until domainRows.length()) {
            val row = domainRows.getJSONObject(index)
            val domain = row.getString("domain")
            restoredDomains[domain] = DomainTrafficStat(domain,
                row.getLong("uploaded").coerceAtLeast(0), row.getLong("downloaded").coerceAtLeast(0))
        }
        val restored = linkedMapOf<String, AppTrafficStat>()
        for (index in 0 until rows.length()) {
            val row = rows.getJSONObject(index)
            val packages = row.getJSONArray("packages")
            val stat = AppTrafficStat(
                row.getString("key"), row.getInt("uid").takeIf { it >= 0 },
                (0 until packages.length()).map { packages.getString(it) },
                row.getLong("uploaded").coerceAtLeast(0), row.getLong("downloaded").coerceAtLeast(0),
            )
            restored[stat.key] = stat
        }
        totals.clear()
        totals.putAll(restored)
        domains.clear()
        domains.putAll(restoredDomains)
        checkpoints.clear()
    }

    companion object {
        const val UNKNOWN_DOMAIN = "__unknown__"
        const val OTHER_DOMAINS = "__other__"
        private const val MAX_DOMAINS = 10_000
    }
}
