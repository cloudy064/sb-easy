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
    private var dirty = false
    private val mutableStats = MutableStateFlow<List<AppTrafficStat>>(emptyList())
    val stats = mutableStats.asStateFlow()
    private val mutableDomains = MutableStateFlow<List<DomainTrafficStat>>(emptyList())
    val domains = mutableDomains.asStateFlow()

    @Synchronized
    fun initialize(context: Context) {
        if (file != null) return
        val target = AtomicFile(File(context.filesDir, "app-traffic.json"))
        file = target
        if (target.baseFile.exists() || File(target.baseFile.path + ".bak").exists()) {
            runCatching { ledger.restore(target.openRead().bufferedReader().use { it.readText() }) }
                .onFailure { ClientDiagnostics.warn("app-traffic", "Could not restore application traffic: ${it.message}") }
        }
        mutableStats.value = ledger.snapshot()
        mutableDomains.value = ledger.domainSnapshot()
    }

    @Synchronized
    fun record(value: ConnectionSnapshot) {
        ledger.record(value)
        dirty = true
    }

    @Synchronized
    fun publish() {
        ledger.prune()
        mutableStats.value = ledger.snapshot()
        mutableDomains.value = ledger.domainSnapshot()
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
        publish()
        flush()
        ledger.newCore()
    }

    @Synchronized
    fun clear() {
        ledger = AppTrafficLedger()
        file?.delete()
        dirty = false
        mutableStats.value = emptyList()
        mutableDomains.value = emptyList()
    }
}
