package io.sbeasy.android.core

import okhttp3.HttpUrl

/** Uses OkHttp's bundled public suffix list, including private suffixes; never resolves DNS. */
internal object TrafficDomain {
    fun host(domain: String, destination: String = ""): String {
        val raw = domain.trim().ifBlank {
            when {
                destination.startsWith("[") -> destination.substringAfter('[').substringBefore(']')
                destination.count { it == ':' } == 1 -> destination.substringBeforeLast(':')
                else -> destination
            }
        }.trim().trimEnd('.')
        if (raw.isBlank()) return AppTrafficLedger.UNKNOWN_HOST
        return runCatching { HttpUrl.Builder().scheme("https").host(raw).build().host }
            .getOrDefault(AppTrafficLedger.UNKNOWN_HOST)
    }

    fun registrable(host: String): String = when (host) {
        AppTrafficLedger.UNKNOWN_HOST -> AppTrafficLedger.UNKNOWN_DOMAIN
        AppTrafficLedger.OTHER_HOST -> AppTrafficLedger.OTHER_DOMAINS
        else -> {
            val url = HttpUrl.Builder().scheme("https").host(host).build()
            if (host.contains(':') || host.matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"))) {
                AppTrafficLedger.IP_DOMAIN
            } else url.topPrivateDomain() ?: host
        }
    }
}
