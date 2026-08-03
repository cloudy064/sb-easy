package io.sbeasy.android.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

object RuntimeObservability {
    private val mutableTraffic = MutableStateFlow(TrafficSnapshot())
    private val mutableGroups = MutableStateFlow<List<ProxyGroupSnapshot>>(emptyList())
    private val mutableConnections = MutableStateFlow<List<ConnectionSnapshot>>(emptyList())
    private val mutableLogs = MutableStateFlow<List<RuntimeLog>>(emptyList())

    val traffic: StateFlow<TrafficSnapshot> = mutableTraffic.asStateFlow()
    val groups: StateFlow<List<ProxyGroupSnapshot>> = mutableGroups.asStateFlow()
    val connections: StateFlow<List<ConnectionSnapshot>> = mutableConnections.asStateFlow()
    val logs: StateFlow<List<RuntimeLog>> = mutableLogs.asStateFlow()

    fun updateTraffic(value: TrafficSnapshot) {
        mutableTraffic.value = value
    }

    fun updateGroups(value: List<ProxyGroupSnapshot>) {
        mutableGroups.value = value
    }

    fun markSelection(groupTag: String, outboundTag: String) {
        mutableGroups.value = mutableGroups.value.map { group ->
            if (group.tag == groupTag) group.copy(selected = outboundTag) else group
        }
    }

    fun updateConnections(value: List<ConnectionSnapshot>) {
        mutableConnections.value = value.sortedByDescending { it.createdAt }.take(300)
    }

    fun appendLogs(value: List<RuntimeLog>) {
        if (value.isEmpty()) return
        mutableLogs.value = (mutableLogs.value + value).takeLast(800)
    }

    fun clearLogs() {
        mutableLogs.value = emptyList()
    }

    fun resetRuntime() {
        mutableTraffic.value = TrafficSnapshot()
        mutableGroups.value = emptyList()
        mutableConnections.value = emptyList()
    }
}

interface ConfigValidator {
    fun validate(content: String)
}

interface RuntimeControl {
    suspend fun applyConfiguration(config: ManagedConfig)
    suspend fun restart()
    suspend fun selectOutbound(groupTag: String, outboundTag: String)
    suspend fun urlTest(groupTag: String)
    suspend fun clearLogs()
}

object RuntimeBridge {
    @Volatile
    var validator: ConfigValidator? = null

    @Volatile
    var control: RuntimeControl? = null
}
