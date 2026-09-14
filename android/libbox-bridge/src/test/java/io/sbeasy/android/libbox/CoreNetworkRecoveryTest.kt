package io.sbeasy.android.libbox

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CancellationException

class CoreNetworkRecoveryTest {
    @Test fun `normal handover resets without rebuilding TUN`() {
        val calls = mutableListOf<String>()
        assertEquals(NetworkRecoveryResult.RESET, recoverCoreNetwork(true, false, { true },
            { calls.add("reset") }, { calls.add("rebuild") }))
        assertEquals(listOf("reset"), calls)
    }
    @Test fun `watchdog escalation bypasses reset and rebuilds`() {
        val calls = mutableListOf<String>()
        assertEquals(NetworkRecoveryResult.REBUILT, recoverCoreNetwork(true, true, { true },
            { calls.add("reset") }, { calls.add("rebuild") }))
        assertEquals(listOf("rebuild"), calls)
    }
    @Test fun `absent core must rebuild`() {
        var rebuilt = false
        recoverCoreNetwork(false, false, { true }, { fail("no core to reset") }, { rebuilt = true })
        assertTrue(rebuilt)
    }
    @Test fun `reset failure falls back to rebuild`() {
        val calls = mutableListOf<String>()
        val result = recoverCoreNetwork(true, false, { true }, { error("reset failed") },
            { calls.add("rebuild") }, { calls.add("reset failed") })
        assertEquals(NetworkRecoveryResult.REBUILT, result)
        assertEquals(listOf("reset failed", "rebuild"), calls)
    }
    @Test fun `network loss during reset prevents rebuild and success`() {
        var current = true
        val result = recoverCoreNetwork(true, false, { current },
            { current = false; error("lost") }, { fail("obsolete rebuild") })
        assertEquals(NetworkRecoveryResult.OBSOLETE, result)
    }
    @Test fun `network loss during native rebuild discards success`() {
        var current = true
        val result = recoverCoreNetwork(false, false, { current }, {}, { current = false })
        assertEquals(NetworkRecoveryResult.OBSOLETE, result)
    }
    @Test(expected = CancellationException::class) fun `cancellation must not rebuild`() {
        recoverCoreNetwork(true, false, { true }, { throw CancellationException() }, { fail("canceled") })
    }
    @Test(expected = IllegalStateException::class) fun `failed rebuild propagates for bounded retry`() {
        recoverCoreNetwork(false, false, { true }, {}, { error("start failed") })
    }
}
