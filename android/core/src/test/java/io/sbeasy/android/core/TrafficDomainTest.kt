package io.sbeasy.android.core

import org.junit.Assert.assertEquals
import org.junit.Test

class TrafficDomainTest {
    @Test fun publicSuffixRulesHandleMultilevelPrivateAndExceptionDomains() {
        val cases = mapOf(
            "api.example.com" to "example.com",
            "img.example.co.uk" to "example.co.uk",
            "cdn.example.com.cn" to "example.com.cn",
            "assets.alice.github.io" to "alice.github.io",
            "images.bob.github.io" to "bob.github.io",
            "a.city.kawasaki.jp" to "city.kawasaki.jp",
            "www.ck" to "www.ck",
        )
        cases.forEach { (host, expected) -> assertEquals(host, expected, TrafficDomain.registrable(host)) }
    }

    @Test fun normalizationHandlesIdnCaseTrailingDotLocalNamesAndIpWithoutDns() {
        assertEquals("api.example.com", TrafficDomain.host(" API.Example.COM. "))
        assertEquals("xn--bcher-kva.de", TrafficDomain.registrable(TrafficDomain.host("shop.bücher.de")))
        assertEquals("localhost", TrafficDomain.registrable("localhost"))
        assertEquals(AppTrafficLedger.IP_DOMAIN, TrafficDomain.registrable("127.0.0.1"))
        assertEquals(AppTrafficLedger.IP_DOMAIN, TrafficDomain.registrable("2001:db8::1"))
        assertEquals(AppTrafficLedger.UNKNOWN_HOST, TrafficDomain.host("not a host"))
    }
}
