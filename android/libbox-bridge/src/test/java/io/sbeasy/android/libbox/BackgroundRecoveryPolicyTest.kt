package io.sbeasy.android.libbox

import org.junit.Assert.*
import org.junit.Test

class BackgroundRecoveryPolicyTest {
    private val wifi = UnderlyingNetwork(1, "wlan0", 10, "address")
    private val cell = UnderlyingNetwork(2, "rmnet_data0", 11, "address")
    @Test fun `two consecutive failures repair but one does not`() {
        val policy = BackgroundRecoveryPolicy()
        assertFalse(policy.record(wifi, false, 0))
        assertTrue(policy.record(wifi, false, 30_000))
    }
    @Test fun `success and network changes reset failure count`() {
        val policy = BackgroundRecoveryPolicy()
        assertFalse(policy.record(wifi, false, 0))
        assertFalse(policy.record(wifi, true, 30_000))
        assertFalse(policy.record(wifi, false, 60_000))
        assertFalse(policy.record(cell, false, 90_000))
        assertFalse(policy.record(null, false, 100_000))
        assertFalse(policy.record(cell, false, 110_000))
        assertTrue(policy.record(cell, false, 140_000))
    }
    @Test fun `outage cannot cause a restart storm even across network changes`() {
        val policy = BackgroundRecoveryPolicy()
        policy.record(wifi, false, 0)
        assertTrue(policy.record(wifi, false, 1))
        assertFalse(policy.record(cell, false, 2))
        assertFalse(policy.record(cell, false, 3))
        assertFalse(policy.record(cell, false, 60_000))
        assertTrue(policy.record(cell, false, 60_001))
    }
}
