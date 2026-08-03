package io.sbeasy.android.core

import android.content.Context
import java.util.UUID

object CoreGraph {
    @Volatile
    private var initialized = false

    lateinit var repository: AgentRepository
        private set

    lateinit var configStore: AtomicConfigStore
        private set

    fun initialize(context: Context) {
        if (initialized) return
        synchronized(this) {
            if (initialized) return
            val application = context.applicationContext
            ClientDiagnostics.initialize(application)
            RuntimeObservability.initialize(application)
            val plainPreferences = application.getSharedPreferences("sb_easy_local", Context.MODE_PRIVATE)
            val installId = plainPreferences.getString("install_id", null) ?: UUID.randomUUID().toString().also {
                plainPreferences.edit().putString("install_id", it).apply()
            }
            configStore = AtomicConfigStore(application)
            repository = AgentRepository(
                SecureEnrollmentStore(application),
                configStore,
                ControlPlaneClient(application),
                installId,
            )
            initialized = true
        }
    }
}
