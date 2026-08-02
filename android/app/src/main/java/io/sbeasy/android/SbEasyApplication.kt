package io.sbeasy.android

import android.app.Application
import io.sbeasy.android.core.CoreGraph
import io.sbeasy.android.core.VpnRuntimeState
import io.sbeasy.android.libbox.LibboxInitializer

class SbEasyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        CoreGraph.initialize(this)
        runCatching { LibboxInitializer.initialize(this) }
            .onFailure { VpnRuntimeState.failed(it.message ?: it.javaClass.simpleName) }
    }
}
