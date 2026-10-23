package io.sbeasy.android.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Explicit, process-local consent. It cannot survive a crash, reboot or VPN stop. */
object CaptureSession {
    private val mutable = MutableStateFlow(false)
    val enabled = mutable.asStateFlow()
    fun authorize() { mutable.value = true }
    fun end() { mutable.value = false }
    fun requireEnabled() { check(mutable.value) { "请先明确启用本次采集会话" } }
    fun effective(config: CaptureConfig, managed: Boolean): CaptureConfig = config.copy(
        enabled = config.enabled && mutable.value,
        autoUpload = config.autoUpload && mutable.value && managed,
    )
}
