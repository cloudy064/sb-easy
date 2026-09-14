package io.sbeasy.android.libbox

/** Two failures on one network trigger repair, with a service-wide restart cooldown. */
internal class BackgroundRecoveryPolicy(private val cooldownMillis: Long = 60_000) {
    private var network: UnderlyingNetwork? = null
    private var failures = 0
    private var lastRepair: Long? = null

    fun record(current: UnderlyingNetwork?, healthy: Boolean, now: Long): Boolean {
        if (network != current) { network = current; failures = 0 }
        if (current == null || healthy) { failures = 0; return false }
        failures++
        if (failures < 2 || lastRepair?.let { now - it < cooldownMillis } == true) return false
        lastRepair = now
        failures = 0
        return true
    }
}
