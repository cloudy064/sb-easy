package io.sbeasy.android.libbox

import android.content.Context
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.SetupOptions
import io.sbeasy.android.core.VpnRuntimeState
import io.sbeasy.android.core.ClientDiagnostics
import io.sbeasy.android.core.ConfigValidator
import io.sbeasy.android.core.RuntimeBridge
import java.io.File
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

object LibboxInitializer {
    private val initialized = AtomicBoolean(false)

    fun initialize(context: Context) {
        if (!initialized.compareAndSet(false, true)) return

        val applicationContext = context.applicationContext
        val workingDirectory = applicationContext.getExternalFilesDir(null)
            ?: File(applicationContext.filesDir, "working")
        workingDirectory.mkdirs()

        Libbox.setLocale(Locale.getDefault().toLanguageTag().replace('-', '_'))
        Libbox.setup(
            SetupOptions().apply {
                basePath = applicationContext.filesDir.path
                workingPath = workingDirectory.path
                tempPath = applicationContext.cacheDir.path
                fixAndroidStack = false
                logMaxLines = 1_000
                debug = false
                crashReportSource = "sb-easy"
            },
        )
        io.sbeasy.android.core.PacketCapture.nativeStatus = { Libbox.captureStatus() }
        io.sbeasy.android.core.PacketCapture.validateFilter = { Libbox.validateCaptureFilter(it) }
        io.sbeasy.android.core.PacketCapture.rotate = { Libbox.rotateCapture() }
        io.sbeasy.android.core.PacketCapture.stopNative = { Libbox.configureCapture("{}") }
        runCatching { Libbox.recoverCapture(io.sbeasy.android.core.PacketCapture.directory(
            io.sbeasy.android.core.CoreGraph.repository.state.value.enrollment).path) }
            .onFailure { ClientDiagnostics.error("PacketCapture", "capture recovery failed", it) }
        val stderrFile = File(workingDirectory, "CrashReport-sb-easy.log")
        ClientDiagnostics.registerAdditionalLog("libbox-stderr", stderrFile)
        ClientDiagnostics.info("LibboxInitializer", "libbox ${Libbox.version()} initialized")
        RuntimeBridge.validator = object : ConfigValidator {
            override fun validate(content: String) = Libbox.checkConfig(content)
        }
        VpnRuntimeState.coreReady(Libbox.version())
    }
}
