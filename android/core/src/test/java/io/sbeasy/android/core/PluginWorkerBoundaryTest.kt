package io.sbeasy.android.core

import org.junit.Assert.*
import org.junit.Test

class PluginWorkerBoundaryTest {
    private val service = PluginServiceBoundary("io.sbeasy.httpdebug.EngineService", true, "io.sbeasy.android.permission.HTTP_DEBUG")
    private fun validate(sharedUid: String? = null, permissions: Set<String> = setOf("android.permission.INTERNET"),
                         activities: Int = 0, receivers: Int = 0, providers: Int = 0, services: List<PluginServiceBoundary> = listOf(service),
                         backup: Boolean = false, debug: Boolean = false, hostDebug: Boolean = false) =
        PluginWorkerBoundary.validate(sharedUid, permissions, activities, receivers, providers, services, backup, debug, hostDebug)

    @Test fun separateUidSignatureServiceAndNetworkOnlyManifestAreAllowed() {
        validate(); validate(debug = true, hostDebug = true)
    }
    @Test fun sharedUidExtraPrivilegesExportedComponentsAndWeakIpcAreRejected() {
        assertTrue(runCatching { validate(sharedUid = "io.sbeasy.android") }.isFailure)
        for (permission in listOf("android.permission.QUERY_ALL_PACKAGES", "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.RECORD_AUDIO")) {
            assertTrue(permission, runCatching { validate(permissions = setOf("android.permission.INTERNET", permission)) }.isFailure)
        }
        assertTrue(runCatching { validate(activities = 1) }.isFailure)
        assertTrue(runCatching { validate(receivers = 1) }.isFailure)
        assertTrue(runCatching { validate(providers = 1) }.isFailure)
        assertTrue(runCatching { validate(services = listOf(service, service.copy(name = "Other"))) }.isFailure)
        assertTrue(runCatching { validate(services = listOf(service.copy(permission = null))) }.isFailure)
        assertTrue(runCatching { validate(services = listOf(service.copy(permission = "android.permission.INTERNET"))) }.isFailure)
        assertTrue(runCatching { validate(backup = true) }.isFailure)
        assertTrue(runCatching { validate(debug = true) }.isFailure)
    }
}
