package io.sbeasy.android.libbox

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class NetworkHandoverTest {
    private fun wifi(id: Long, links: String = "address=192.168.1.2") = UnderlyingNetwork(id, "wlan0", 25, links)
    private fun cellular() = UnderlyingNetwork(113, "rmnet_data3", 24, "mobile")

    @Test fun `watchdog can force recovery on an unchanged network`() = runTest {
        var calls = 0
        val handover = NetworkHandover(this) { _, _ -> calls++; true }
        handover.changed(wifi(1)); advanceTimeBy(1_200); runCurrent()
        handover.changed(wifi(1), force = true); advanceTimeBy(1_200); runCurrent()
        assertEquals(2, calls)
    }

    @Test fun `pending protection covers debounce and is released on loss or completion`() = runTest {
        val protection = mutableListOf<Boolean>()
        val handover = NetworkHandover(this, onPendingChanged = { protection.add(it) }) { _, _ -> true }
        handover.changed(wifi(1))
        assertTrue(handover.pending)
        handover.changed(null)
        assertFalse(handover.pending)
        runCurrent()
        assertEquals(listOf(true, false), protection)
        handover.changed(wifi(2)); advanceTimeBy(1_200); runCurrent()
        assertFalse(handover.pending)
        assertEquals(listOf(true, false, true, false), protection)
    }

    @Test fun `loss cancels the queued restart for a disappeared wifi`() = runTest {
        val calls = mutableListOf<UnderlyingNetwork>()
        val handover = NetworkHandover(this) { network, _ -> calls.add(network); true }
        handover.changed(wifi(108)); runCurrent()
        advanceTimeBy(200)
        handover.changed(null)
        advanceTimeBy(2_000); runCurrent()
        assertTrue(calls.isEmpty())
    }

    @Test fun `rapid wifi cellular wifi changes only restart the final network`() = runTest {
        val calls = mutableListOf<UnderlyingNetwork>()
        val handover = NetworkHandover(this) { network, _ -> calls.add(network); true }
        handover.changed(wifi(107)); runCurrent(); advanceTimeBy(400)
        handover.changed(cellular()); runCurrent(); advanceTimeBy(400)
        handover.changed(wifi(108)); runCurrent(); advanceTimeBy(1_200); runCurrent()
        assertEquals(listOf(wifi(108)), calls)
    }

    @Test fun `two wifi networks with the same interface are distinct handovers`() = runTest {
        val calls = mutableListOf<UnderlyingNetwork>()
        val handover = NetworkHandover(this) { network, _ -> calls.add(network); true }
        handover.changed(wifi(107)); runCurrent(); advanceTimeBy(1_200); runCurrent()
        handover.changed(wifi(108)); runCurrent(); advanceTimeBy(1_200); runCurrent()
        assertEquals(listOf(wifi(107), wifi(108)), calls)
    }

    @Test fun `same network recovered after a loss must restart again`() = runTest {
        var count = 0
        val handover = NetworkHandover(this) { _, _ -> count++; true }
        handover.changed(wifi(107)); runCurrent(); advanceTimeBy(1_200); runCurrent()
        handover.changed(null)
        handover.changed(wifi(107)); runCurrent(); advanceTimeBy(1_200); runCurrent()
        assertEquals(2, count)
    }

    @Test fun `duplicate capabilities do not postpone a pending recovery`() = runTest {
        var count = 0
        val handover = NetworkHandover(this) { _, _ -> count++; true }
        handover.changed(wifi(107)); runCurrent(); advanceTimeBy(1_000)
        handover.changed(wifi(107)); advanceTimeBy(200); runCurrent()
        assertEquals(1, count)
    }

    @Test fun `address or dns changes on the same network trigger recovery`() = runTest {
        var count = 0
        val handover = NetworkHandover(this) { _, _ -> count++; true }
        handover.changed(wifi(107)); runCurrent(); advanceTimeBy(1_200); runCurrent()
        handover.changed(wifi(107, "address=192.168.2.2")); runCurrent(); advanceTimeBy(1_200); runCurrent()
        assertEquals(2, count)
    }

    @Test fun `network loss invalidates native work that cannot be canceled`() = runTest {
        val accepted = mutableListOf<UnderlyingNetwork>()
        val handover = NetworkHandover(this) { network, current ->
            withContext(NonCancellable) { delay(300); if (current()) accepted.add(network) }
            true
        }
        handover.changed(wifi(107)); runCurrent(); advanceTimeBy(1_200); runCurrent()
        handover.changed(null); advanceTimeBy(300); runCurrent()
        assertTrue(accepted.isEmpty())
    }

    @Test fun `failed native startup retries and stops after success`() = runTest {
        var attempts = 0
        val handover = NetworkHandover(this) { _, _ -> ++attempts == 2 }
        handover.changed(wifi(107)); runCurrent(); advanceTimeBy(1_200); runCurrent()
        assertEquals(1, attempts)
        advanceTimeBy(2_000); runCurrent(); advanceTimeBy(4_000); runCurrent()
        assertEquals(2, attempts)
    }

    @Test fun `retries are bounded and close invalidates queued work`() = runTest {
        var attempts = 0
        val handover = NetworkHandover(this) { _, _ -> attempts++; false }
        handover.changed(wifi(107)); runCurrent(); advanceTimeBy(8_000); runCurrent()
        assertEquals(3, attempts)
        handover.changed(wifi(108)); runCurrent(); handover.close()
        advanceTimeBy(8_000); runCurrent()
        assertEquals(3, attempts)
    }

    @Test fun `validated cellular outranks unvalidated wifi and blocked networks`() {
        val mobile = cellular()
        assertEquals(mobile, preferredNetwork(listOf(
            NetworkCandidate(wifi(107), false, 30), NetworkCandidate(mobile, true, 10),
        ), wifi(107)))
        assertEquals(mobile, preferredNetwork(listOf(
            NetworkCandidate(wifi(107), true, 30, blocked = true), NetworkCandidate(mobile, true, 10),
        ), wifi(107)))
        assertEquals(wifi(107), preferredNetwork(listOf(
            NetworkCandidate(wifi(107), true, 30), NetworkCandidate(mobile, true, 10),
        ), mobile))
        assertNull(preferredNetwork(emptyList(), mobile))
    }
}
