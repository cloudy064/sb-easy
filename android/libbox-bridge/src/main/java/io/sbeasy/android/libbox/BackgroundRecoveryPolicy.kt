package io.sbeasy.android.libbox

/** A failed remote endpoint is not proof of a broken core. Allow one repair per outage. */
internal class BackgroundRecoveryPolicy(
    private val failureWindowMillis: Long = 90_000,
    private val stableWindowMillis: Long = 120_000,
    private val cooldownMillis: Long = 300_000,
) {
    private var network: UnderlyingNetwork? = null
    private var failures = 0
    private var failedSince: Long? = null
    private var healthySince: Long? = null
    private var lastSample: Long? = null
    private var lastRepair: Long? = null
    private var repairedThisOutage = false

    fun record(current: UnderlyingNetwork?, healthy: Boolean, now: Long): Boolean {
        // Screen-on bursts must not count as sustained failure, and a long sleep must
        // not count as sustained health. Network churn cannot refill the repair budget.
        if (network != current || lastSample?.let { now - it > 60_000 } == true) {
            network = current
            failures = 0
            failedSince = null
            healthySince = null
        }
        lastSample = now
        if (current == null || healthy) {
            failures = 0
            failedSince = null
            if (current == null) healthySince = null
            else {
                val since = healthySince ?: now.also { healthySince = it }
                if (now - since >= stableWindowMillis) repairedThisOutage = false
            }
            return false
        }
        healthySince = null
        val since = failedSince ?: now.also { failedSince = it }
        failures++
        if (failures < 3 || now - since < failureWindowMillis || repairedThisOutage ||
            lastRepair?.let { now - it < cooldownMillis } == true) return false
        lastRepair = now
        repairedThisOutage = true
        return true
    }
}
