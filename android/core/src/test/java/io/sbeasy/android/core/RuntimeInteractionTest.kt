package io.sbeasy.android.core

import org.junit.Assert.assertEquals
import org.junit.Test

class RuntimeInteractionTest {
    @Test
    fun selectedOutboundIsReflectedImmediately() {
        RuntimeObservability.updateGroups(
            listOf(
                ProxyGroupSnapshot(
                    tag = "Proxy",
                    type = "selector",
                    selectable = true,
                    selected = "auto",
                    items = emptyList(),
                ),
            ),
        )

        RuntimeObservability.markSelection("Proxy", "Hong Kong")

        assertEquals("Hong Kong", RuntimeObservability.groups.value.single().selected)
        RuntimeObservability.resetRuntime()
    }

    @Test
    fun routeConnectionMatchesResolvedDestination() {
        val expected = connection(destination = "203.0.113.8:443")

        val matched = findRouteTestConnection(
            candidates = listOf(expected, connection(destination = "192.0.2.1:53", network = "udp")),
            host = "example.com",
            addresses = setOf("203.0.113.8"),
        )

        assertEquals(expected.id, matched?.id)
    }

    @Test
    fun domainRouteStatsAggregateConnectionsTrafficAndRoutes() {
        RuntimeObservability.resetDomainRouteStats()
        val direct = connection("1.1.1.1:443").copy(
            id = "direct-1",
            domain = "Example.COM.",
            outbound = "direct",
            outboundType = "direct",
            chain = listOf("direct"),
            rule = "domain_suffix=example.com",
        )
        RuntimeObservability.recordConnectionOpened(direct.id, direct)
        RuntimeObservability.recordConnectionTraffic(direct.id, 120, 800)
        RuntimeObservability.recordConnectionClosed(
            direct.id,
            direct.copy(uplinkTotal = 150, downlinkTotal = 1_000, closedAt = 2L),
        )

        val proxy = direct.copy(
            id = "proxy-1",
            outbound = "Proxy",
            outboundType = "selector",
            chain = listOf("Proxy", "Hong Kong"),
            rule = "final",
        )
        RuntimeObservability.recordConnectionOpened(proxy.id, proxy)
        RuntimeObservability.recordConnectionTraffic(proxy.id, 50, 400)

        val stats = RuntimeObservability.domainRouteStats()
        RuntimeObservability.refreshDomainRouteStats()
        assertEquals(2, stats.size)
        assertEquals(2, RuntimeObservability.domainRoutes.value.size)
        val directStat = stats.single { it.outbound == "direct" }
        assertEquals("example.com", directStat.domain)
        assertEquals(1L, directStat.connectionCount)
        assertEquals(150L, directStat.uplinkTotal)
        assertEquals(1_000L, directStat.downlinkTotal)
        assertEquals(listOf("Proxy", "Hong Kong"), stats.single { it.outbound == "Proxy" }.chain)
        RuntimeObservability.resetDomainRouteStats()
    }

    @Test
    fun domainRouteStatsFallBackToDestinationAddress() {
        RuntimeObservability.resetDomainRouteStats()
        val value = connection("203.0.113.8:443").copy(id = "ip-1", outbound = "direct", chain = listOf("direct"))
        RuntimeObservability.recordConnectionOpened(value.id, value)

        assertEquals("203.0.113.8", RuntimeObservability.domainRouteStats().single().domain)
        RuntimeObservability.resetDomainRouteStats()
    }

    private fun connection(destination: String, network: String = "tcp") = ConnectionSnapshot(
        id = destination,
        network = network,
        source = "172.19.0.1:12345",
        destination = destination,
        domain = "",
        protocol = "",
        createdAt = 1L,
        closedAt = 0L,
        uplink = 0L,
        downlink = 0L,
        uplinkTotal = 0L,
        downlinkTotal = 0L,
        rule = "",
        outbound = "Proxy",
        outboundType = "selector",
        chain = listOf("Hong Kong"),
    )
}
