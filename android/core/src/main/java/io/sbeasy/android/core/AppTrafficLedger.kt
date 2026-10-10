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

/** One ledger per embedded-core lifetime; totals alone survive process restarts. */
class AppTrafficLedger {
    private data class Checkpoint(val key: String, val up: Long, val down: Long, val closedAt: Long)
    private val totals = linkedMapOf<String, AppTrafficStat>()
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
        checkpoints[value.id] = Checkpoint(key, up, down, maxOf(value.closedAt, previous?.closedAt ?: 0))
    }

    fun prune() {
        // libbox replays up to 1,000 closed connections on stream reconnect.
        checkpoints.entries.filter { it.value.closedAt > 0 }
            .sortedByDescending { it.value.closedAt }.drop(2_000)
            .forEach { checkpoints.remove(it.key) }
    }

    fun newCore() = checkpoints.clear()

    fun snapshot(): List<AppTrafficStat> = totals.values.sortedByDescending { it.uploaded + it.downloaded }

    fun encode(): String = JSONArray().apply {
        totals.values.forEach { stat ->
            put(JSONObject().put("key", stat.key).put("uid", stat.uid ?: -1)
                .put("packages", JSONArray(stat.packages))
                .put("uploaded", stat.uploaded).put("downloaded", stat.downloaded))
        }
    }.toString()

    fun restore(payload: String) {
        val rows = JSONArray(payload)
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
        checkpoints.clear()
    }
}
