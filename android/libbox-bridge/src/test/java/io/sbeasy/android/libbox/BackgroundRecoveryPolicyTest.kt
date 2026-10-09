package io.sbeasy.android.libbox

import org.junit.Assert.*
import org.junit.Test

class BackgroundRecoveryPolicyTest {
    private val wifi = UnderlyingNetwork(1, "wlan0", 10, "address")
    private val cell = UnderlyingNetwork(2, "rmnet_data0", 11, "address")

    @Test fun `short failures and event bursts cannot rebuild the core`() {
        val policy = BackgroundRecoveryPolicy()
        for (now in listOf(0L, 1L, 2L, 10_000L, 30_000L, 60_000L)) {
            assertFalse(policy.record(wifi, false, now))
        }
        assertTrue(policy.record(wifi, false, 90_000))
    }

    @Test fun `persistent outage repairs only once even across network churn`() {
        val policy = BackgroundRecoveryPolicy()
        var repairs = 0
        for (now in 0L..3_600_000L step 30_000L) {
            val network = if (now < 600_000 || now % 120_000 < 60_000) wifi else cell
            if (policy.record(network, false, now)) repairs++
        }
        assertEquals(1, repairs)
    }

    @Test fun `intermittent successful probes do not refill the outage budget`() {
        val policy = BackgroundRecoveryPolicy()
        for (now in 0L..60_000L step 30_000L) assertFalse(policy.record(wifi, false, now))
        assertTrue(policy.record(wifi, false, 90_000))
        for (now in 120_000L..3_600_000L step 30_000L) {
            assertFalse(policy.record(wifi, now % 300_000L == 0L, now))
        }
    }

    @Test fun `sustained recovery rearms one later repair`() {
        val policy = BackgroundRecoveryPolicy()
        for (now in 0L..60_000L step 30_000L) policy.record(wifi, false, now)
        assertTrue(policy.record(wifi, false, 90_000))
        for (now in 120_000L..240_000L step 30_000L) assertFalse(policy.record(wifi, true, now))
        // New outage is qualified after 90s, but the global 5 minute cooldown still applies.
        for (now in 270_000L..360_000L step 30_000L) assertFalse(policy.record(wifi, false, now))
        assertTrue(policy.record(wifi, false, 390_000))
    }

    @Test fun `sleep and absent network cannot masquerade as stable health`() {
        val policy = BackgroundRecoveryPolicy()
        for (now in 0L..60_000L step 30_000L) policy.record(wifi, false, now)
        assertTrue(policy.record(wifi, false, 90_000))
        assertFalse(policy.record(wifi, true, 120_000))
        assertFalse(policy.record(wifi, true, 600_000))
        assertFalse(policy.record(null, false, 610_000))
        for (now in 630_000L..900_000L step 30_000L) assertFalse(policy.record(wifi, false, now))
    }

    @Test fun `network changes restart failure qualification`() {
        val policy = BackgroundRecoveryPolicy()
        for (now in 0L..60_000L step 30_000L) assertFalse(policy.record(wifi, false, now))
        for (now in 90_000L..150_000L step 30_000L) assertFalse(policy.record(cell, false, now))
        assertTrue(policy.record(cell, false, 180_000))
    }
}
