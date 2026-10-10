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
        assertEquals(DomainTrafficStat("example.com", 8, 10), restored.domainSnapshot().first())
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

    @Test fun detailLimitRetainsOverflowBytesInsteadOfDroppingTraffic() {
        val ledger = AppTrafficLedger(maxDetailRows = 3)
        repeat(5) { ledger.record(connection(id = "$it", up = 1).copy(domain = "host$it.example.com")) }
        assertEquals(4, ledger.detailSnapshot().size)
        assertEquals(2L, ledger.domainSnapshot().single { it.domain == AppTrafficLedger.OTHER_DOMAINS }.uploaded)
        assertEquals(5L, ledger.domainSnapshot().sumOf { it.uploaded })
        assertEquals(5L, ledger.snapshot().sumOf { it.uploaded })
    }


    @Test fun registrableDomainKeepsHostsAppsAndActualExitsSeparate() {
        val ledger = AppTrafficLedger()
        ledger.record(connection(id = "api-proxy", up = 100, down = 200).copy(domain = "api.example.co.uk", outbound = "Tokyo", outboundType = "http", chain = listOf("Tokyo", "default")))
        ledger.record(connection(id = "api-direct", up = 10, down = 20).copy(domain = "api.example.co.uk"))
        ledger.record(connection(id = "cdn", up = 30, down = 40).copy(domain = "cdn.example.co.uk", outbound = "US", outboundType = "trojan"))
        ledger.record(connection(id = "second-app", uid = 10002, up = 1, down = 2).copy(domain = "api.example.co.uk"))
        assertEquals(listOf(DomainTrafficStat("example.co.uk", 141, 262)), ledger.domainSnapshot())
        val appKey = ledger.snapshot().single { it.uid == 10001 }.key
        val appHosts = trafficHosts(ledger.detailSnapshot().filter { it.key.appKey == appKey })
        assertEquals(setOf("api.example.co.uk", "cdn.example.co.uk"), appHosts.map { it.host }.toSet())
        val api = appHosts.single { it.host == "api.example.co.uk" }
        assertEquals(110L, api.uploaded)
        assertEquals(setOf(TrafficRoute.DIRECT, TrafficRoute.PROXY), api.exits.map { it.exit.route }.toSet())
        assertEquals("Tokyo", api.exits.single { it.exit.route == TrafficRoute.PROXY }.exit.outbound)
        assertEquals(listOf("Tokyo", "default"), api.exits.single { it.exit.route == TrafficRoute.PROXY }.exit.chain)
        val domainHosts = trafficHosts(ledger.detailSnapshot().filter { it.key.domain == "example.co.uk" })
        assertEquals(111L, domainHosts.single { it.host == "api.example.co.uk" }.uploaded)
    }

    @Test fun replayAndMissingClosingMetadataDoNotMoveHistoricalExit() {
        val ledger = AppTrafficLedger()
        val first = connection(up = 10, down = 20).copy(domain = "api.example.com", outbound = "Tokyo", outboundType = "http")
        ledger.record(first)
        ledger.record(first.copy(uplinkTotal = 30, downlinkTotal = 40))
        ledger.record(connection(up = 35, down = 45, closed = 100))
        ledger.record(first.copy(uplinkTotal = 35, downlinkTotal = 45, closedAt = 100))
        ledger.record(connection(id = "after-switch", up = 5, down = 10).copy(domain = "api.example.com", outbound = "US", outboundType = "http"))
        assertEquals(40L, ledger.domainSnapshot().single().uploaded)
        assertEquals(2, ledger.detailSnapshot().size)
        assertEquals(35L, ledger.detailSnapshot().single { it.key.outbound == "Tokyo" }.uploaded)
        val restored = AppTrafficLedger().apply { restore(ledger.encode()) }
        assertEquals(ledger.statistics(), restored.statistics())
    }

    @Test fun upgrading125GroupsHostsButDoesNotInventAppOrExitAttribution() {
        val ledger = AppTrafficLedger()
        ledger.restore("""{"version":2,"apps":[{"key":"10001:example.app","uid":10001,"packages":["example.app"],"uploaded":300,"downloaded":600}],
            "domains":[{"domain":"API.EXAMPLE.CO.UK.","uploaded":100,"downloaded":200},{"domain":"cdn.example.co.uk","uploaded":200,"downloaded":400}]}""")
        assertEquals(listOf(DomainTrafficStat("example.co.uk", 300, 600)), ledger.domainSnapshot())
        assertEquals(setOf("api.example.co.uk", "cdn.example.co.uk"), ledger.detailSnapshot().map { it.key.host }.toSet())
        assertEquals(0, ledger.detailSnapshot().count { it.key.appKey == "10001:example.app" })
        assertEquals(true, ledger.detailSnapshot().all { it.key.legacy && it.key.route == TrafficRoute.UNKNOWN })
        ledger.record(connection(up = 5, down = 10).copy(domain = "api.example.co.uk"))
        assertEquals(305L, ledger.snapshot().single().uploaded)
        assertEquals(5L, ledger.detailSnapshot().single { !it.key.legacy }.uploaded)
        val restored = AppTrafficLedger().apply { restore(ledger.encode()) }
        assertEquals(ledger.statistics(), restored.statistics())
    }

    @Test fun ipDestinationsStayVisibleWithoutPretendingTheyAreDomains() {
        val ledger = AppTrafficLedger()
        ledger.record(connection(up = 5).copy(destination = "203.0.113.7:443"))
        ledger.record(connection(id = "ipv6", up = 7).copy(destination = "[2001:db8::1]:443"))
        assertEquals(listOf(DomainTrafficStat(AppTrafficLedger.IP_DOMAIN, 12, 0)), ledger.domainSnapshot())
        assertEquals(setOf("203.0.113.7", "2001:db8::1"), ledger.detailSnapshot().map { it.key.host }.toSet())
    }

}
