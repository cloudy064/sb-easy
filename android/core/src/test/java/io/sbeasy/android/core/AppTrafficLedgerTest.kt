package io.sbeasy.android.core

import org.junit.Assert.assertEquals
import org.junit.Test

class AppTrafficLedgerTest {
    private fun connection(id: String = "a", up: Long = 0, down: Long = 0, uid: Int? = 10001,
                           packages: List<String> = listOf("example.app"), closed: Long = 0) = ConnectionSnapshot(
        id, "tcp", "", "", "", "", 1, closed, 0, 0, up, down, "", "direct", "direct", emptyList(), uid, packages,
    )

    @Test fun snapshotsUpdatesAndFinalTotalsCountEachByteOnce() {
        val ledger = AppTrafficLedger()
        ledger.record(connection(up = 10, down = 20))
        ledger.record(connection(up = 40, down = 80))
        ledger.record(connection(up = 50, down = 100, closed = 100))
        // The command stream replays both active and recently closed snapshots.
        ledger.record(connection(up = 50, down = 100, closed = 100))
        ledger.record(connection(up = 40, down = 80))
        assertEquals(50L, ledger.snapshot().single().uploaded)
        assertEquals(100L, ledger.snapshot().single().downloaded)
    }

    @Test fun sharedUidIsOneBucketRegardlessOfPackageOrderAndUnknownIsSeparate() {
        val ledger = AppTrafficLedger()
        ledger.record(connection(up = 10, packages = listOf("b", "a")))
        ledger.record(connection(id = "b", up = 20, packages = listOf("a", "b", "a")))
        ledger.record(connection(id = "unknown", down = 40, uid = null, packages = emptyList()))
        assertEquals(2, ledger.snapshot().size)
        assertEquals(30L, ledger.snapshot().single { it.uid != null }.uploaded)
        assertEquals(listOf("a", "b"), ledger.snapshot().single { it.uid != null }.packages)
        assertEquals(40L, ledger.snapshot().single { it.uid == null }.downloaded)
    }

    @Test fun coreRestartAndPersistenceKeepTotalsAndAllowFreshConnectionIds() {
        val ledger = AppTrafficLedger()
        ledger.record(connection(up = 100, down = 200))
        ledger.newCore()
        ledger.record(connection(up = 10, down = 20))
        val restored = AppTrafficLedger().apply { restore(ledger.encode()) }
        restored.record(connection(up = 1, down = 2))
        assertEquals(111L, restored.snapshot().single().uploaded)
        assertEquals(222L, restored.snapshot().single().downloaded)
    }

    @Test fun closedConnectionWithoutOpenAndMissingFinalIdentityAreHandled() {
        val ledger = AppTrafficLedger()
        ledger.record(connection(up = 3, down = 4))
        ledger.record(connection(up = 10, down = 12, uid = null, packages = emptyList(), closed = 100))
        ledger.record(connection(id = "missed", up = 2, down = 3, closed = 100))
        assertEquals(12L, ledger.snapshot().single().uploaded)
        assertEquals(15L, ledger.snapshot().single().downloaded)
    }

    @Test fun recentClosedHistoryIsDeduplicatedAfterPruning() {
        val ledger = AppTrafficLedger()
        repeat(3000) { ledger.record(connection(id = "$it", up = 1, closed = it + 1L)) }
        ledger.prune()
        for (i in 2000 until 3000) ledger.record(connection(id = "$i", up = 1, closed = i + 1L))
        assertEquals(3000L, ledger.snapshot().single().uploaded)
    }

    @Test fun packageReinstallWithReusedUidAndOtherAndroidUsersStaySeparate() {
        val ledger = AppTrafficLedger()
        ledger.record(connection(up = 1))
        ledger.record(connection(id = "reinstalled", up = 2, packages = listOf("another.app")))
        ledger.record(connection(id = "profile", up = 3, uid = 110001))
        assertEquals(3, ledger.snapshot().size)
    }
    @Test fun domainsAggregateAcrossAppsAndRoutesWithoutReplayingBytes() {
        val ledger = AppTrafficLedger()
        ledger.record(connection(up = 10, down = 20).copy(domain = "Example.COM."))
        ledger.record(connection(up = 30, down = 40).copy(domain = "example.com"))
        ledger.record(connection(up = 30, down = 40, closed = 100).copy(domain = "example.com"))
        ledger.record(connection(id = "b", up = 5, down = 10, uid = 10002).copy(domain = "example.com", outbound = "proxy"))
        assertEquals(listOf(DomainTrafficStat("example.com", 35, 50)), ledger.domainSnapshot())
        assertEquals(35L, ledger.snapshot().sumOf { it.uploaded })
    }

    @Test fun missingDomainIsSeparateAndDomainTotalsSurviveRestart() {
        val ledger = AppTrafficLedger()
        ledger.record(connection(up = 1, down = 2))
        ledger.record(connection(id = "b", up = 3, down = 4).copy(domain = "cdn.example.com"))
        val restored = AppTrafficLedger().apply { restore(ledger.encode()) }
        assertEquals(ledger.domainSnapshot(), restored.domainSnapshot())
        restored.newCore()
        restored.record(connection(up = 5, down = 6).copy(domain = "cdn.example.com"))
        assertEquals(DomainTrafficStat("cdn.example.com", 8, 10), restored.domainSnapshot().first())
        assertEquals(DomainTrafficStat(AppTrafficLedger.UNKNOWN_DOMAIN, 1, 2), restored.domainSnapshot().last())
    }

    @Test fun upgrading124PreservesAppHistoryWithoutInventingDomainHistory() {
        val ledger = AppTrafficLedger()
        ledger.restore("""[{"key":"10001:example.app","uid":10001,"packages":["example.app"],"uploaded":100,"downloaded":200}]""")
        assertEquals(100L, ledger.snapshot().single().uploaded)
        assertEquals(emptyList<DomainTrafficStat>(), ledger.domainSnapshot())
        ledger.record(connection(up = 5, down = 10).copy(domain = "example.com"))
        val restored = AppTrafficLedger().apply { restore(ledger.encode()) }
        assertEquals(105L, restored.snapshot().single().uploaded)
        assertEquals(listOf(DomainTrafficStat("example.com", 5, 10)), restored.domainSnapshot())
    }

    @Test fun domainLimitRetainsOverflowBytesInsteadOfDroppingTraffic() {
        val ledger = AppTrafficLedger()
        repeat(10005) { ledger.record(connection(id = "$it", up = 1).copy(domain = "host$it.example.com")) }
        assertEquals(10001, ledger.domainSnapshot().size)
        assertEquals(5L, ledger.domainSnapshot().single { it.domain == AppTrafficLedger.OTHER_DOMAINS }.uploaded)
        assertEquals(10005L, ledger.domainSnapshot().sumOf { it.uploaded })
    }

}
