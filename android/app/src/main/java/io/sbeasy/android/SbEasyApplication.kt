package io.sbeasy.android

import android.app.Application
import io.sbeasy.android.core.CoreGraph
import io.sbeasy.android.core.VpnRuntimeState
import io.sbeasy.android.core.PluginTrustStore
import io.sbeasy.android.libbox.LibboxInitializer

class SbEasyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        PluginTrustStore.initialize(this, String(android.util.Base64.decode(BuildConfig.PLUGIN_CATALOG_KEYS_BASE64, android.util.Base64.DEFAULT), Charsets.UTF_8), BuildConfig.VERSION_NAME)
        io.sbeasy.android.core.AppUpdateStore.initialize(this, String(android.util.Base64.decode(BuildConfig.APP_CATALOG_KEYS_BASE64, android.util.Base64.DEFAULT), Charsets.UTF_8))
        CoreGraph.initialize(this)
        runCatching { LibboxInitializer.initialize(this) }
            .onFailure { VpnRuntimeState.failed(it.message ?: it.javaClass.simpleName) }
        SubscriptionRefreshService.schedule(this)
    }
}
