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
