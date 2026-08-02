package io.sbeasy.android.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class VpnPhase {
    DISCONNECTED,
    STARTING,
    CONNECTED,
    STOPPING,
    ERROR,
}

data class VpnSnapshot(
    val phase: VpnPhase = VpnPhase.DISCONNECTED,
    val detail: String = "等待连接",
    val coreVersion: String? = null,
    val startedAtMillis: Long? = null,
    val error: String? = null,
    val configEtag: String? = null,
    val ruleSource: String? = null,
    val profileName: String? = null,
)

object VpnRuntimeState {
    private val mutableState = MutableStateFlow(VpnSnapshot())
    val state: StateFlow<VpnSnapshot> = mutableState.asStateFlow()

    fun coreReady(version: String) {
        mutableState.value = mutableState.value.copy(coreVersion = version)
    }

    fun starting() {
        mutableState.value = mutableState.value.copy(
            phase = VpnPhase.STARTING,
            detail = "正在建立 Android TUN",
            error = null,
        )
    }

    fun connected(config: ManagedConfig?) {
        mutableState.value = mutableState.value.copy(
            phase = VpnPhase.CONNECTED,
            detail = "受管代理运行中",
            startedAtMillis = System.currentTimeMillis(),
            error = null,
            configEtag = config?.etag,
            ruleSource = config?.ruleSource,
            profileName = config?.profileName,
        )
    }

    fun stopping() {
        mutableState.value = mutableState.value.copy(
            phase = VpnPhase.STOPPING,
            detail = "正在关闭 VPN",
        )
    }

    fun disconnected() {
        mutableState.value = mutableState.value.copy(
            phase = VpnPhase.DISCONNECTED,
            detail = "等待连接",
            startedAtMillis = null,
            error = null,
        )
    }

    fun failed(message: String) {
        mutableState.value = mutableState.value.copy(
            phase = VpnPhase.ERROR,
            detail = "VPN 启动失败",
            startedAtMillis = null,
            error = message,
        )
    }

    fun configurationChanged(config: ManagedConfig) {
        mutableState.value = mutableState.value.copy(
            configEtag = config.etag,
            ruleSource = config.ruleSource,
            profileName = config.profileName,
            error = null,
        )
    }

    fun runtimeWarning(message: String) {
        mutableState.value = mutableState.value.copy(error = message)
    }
}
