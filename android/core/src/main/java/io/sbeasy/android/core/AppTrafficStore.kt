package io.sbeasy.android.core

import android.content.Context
import android.os.SystemClock
import android.util.AtomicFile
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Local-only accounting. This data is never included in agent telemetry. */
object AppTrafficStore {
    private var ledger = AppTrafficLedger()
    private var file: AtomicFile? = null
    private var lastSave = 0L
    private var lastPublish = 0L
    private var dirty = false
    private val mutableState = MutableStateFlow(TrafficStatisticsSnapshot())
    val state = mutableState.asStateFlow()

    @Synchronized
    fun initialize(context: Context) {
        if (file != null) return
        val target = AtomicFile(File(context.filesDir, "app-traffic.json"))
        file = target
        if (target.baseFile.exists() || File(target.baseFile.path + ".bak").exists()) {
            runCatching { ledger.restore(target.openRead().bufferedReader().use { it.readText() }) }
                .onFailure { ClientDiagnostics.warn("app-traffic", "Could not restore application traffic: ${it.message}") }
        }
        mutableState.value = ledger.statistics()
    }

    @Synchronized
    fun record(value: ConnectionSnapshot) {
        ledger.record(value)
        dirty = true
    }

    @Synchronized
    fun publish(force: Boolean = false) {
        val now = SystemClock.elapsedRealtime()
        if (!force && now - lastPublish < 1_000) return
        lastPublish = now
        ledger.prune()
        mutableState.value = ledger.statistics()
        if (SystemClock.elapsedRealtime() - lastSave >= 30_000) flush()
    }

    @Synchronized
    fun flush() {
        val target = file ?: return
        if (!dirty) return
        runCatching {
            val stream = target.startWrite()
            try {
                stream.write(ledger.encode().toByteArray(Charsets.UTF_8))
                target.finishWrite(stream)
            } catch (error: Throwable) {
                target.failWrite(stream)
                throw error
            }
            dirty = false
            lastSave = SystemClock.elapsedRealtime()
        }.onFailure { ClientDiagnostics.warn("app-traffic", "Could not save application traffic: ${it.message}") }
    }

    @Synchronized
    fun endCore() {
        publish(force = true)
        flush()
        ledger.newCore()
    }

    @Synchronized
    fun clear() {
        ledger = AppTrafficLedger()
        file?.delete()
        dirty = false
        mutableState.value = TrafficStatisticsSnapshot()
    }
}
