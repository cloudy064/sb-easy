/* SPDX-License-Identifier: GPL-3.0-or-later */
package io.sbeasy.android.libbox

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.SystemProxyStatus
import io.sbeasy.android.core.VpnRuntimeState
import io.sbeasy.android.core.CoreGraph
import io.sbeasy.android.core.ManagedConfig
import io.sbeasy.android.core.ProxyGroupSnapshot
import io.sbeasy.android.core.RuntimeBridge
import io.sbeasy.android.core.RuntimeControl
import io.sbeasy.android.core.RuntimeObservability
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class SbEasyVpnService : VpnService(), CommandServerHandler, RuntimeControl {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lifecycleMutex = Mutex()
    private lateinit var platform: AndroidPlatformBridge
    private var commandServer: CommandServer? = null
    private var commandMonitor: LibboxCommandMonitor? = null
    private val restoredSelectionGroups = mutableSetOf<String>()
    private var controlLoopJob: Job? = null
    private var tunDescriptor: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        LibboxInitializer.initialize(this)
        platform = AndroidPlatformBridge(this)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            serviceScope.launch { stopRuntime(stopService = true) }
            return Service.START_NOT_STICKY
        }

        startForegroundNotification("正在同步受管配置")
        serviceScope.launch { startRuntime() }
        return Service.START_STICKY
    }

    override fun onBind(intent: Intent): IBinder? = super.onBind(intent)

    override fun onRevoke() {
        serviceScope.launch { stopRuntime(stopService = true) }
    }

    override fun onDestroy() {
        runBlocking(Dispatchers.IO) { closeResources() }
        serviceScope.cancel()
        super.onDestroy()
    }

    internal fun attachTun(descriptor: ParcelFileDescriptor) {
        tunDescriptor?.close()
        tunDescriptor = descriptor
    }

    internal fun updateUnderlyingNetwork(network: Network?) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1 && tunDescriptor != null) {
            setUnderlyingNetworks(network?.let { arrayOf(it) })
        }
    }

    private suspend fun startRuntime() {
        try {
            runCatching { CoreGraph.repository.syncConfiguration() }
            val config = requireNotNull(CoreGraph.repository.activeConfig()) {
                "尚未取得可用配置，请先在 App 中完成设备注册"
            }
            lifecycleMutex.withLock {
            if (commandServer != null) return
            VpnRuntimeState.starting()
                platform.start()
                startCore(config)
                RuntimeBridge.control = this
                VpnRuntimeState.connected(config)
                startForegroundNotification("${config.profileName} · 代理运行中")
                startControlLoop()
            }
        } catch (error: Throwable) {
            Log.e(TAG, "Failed to start libbox", error)
            closeResources()
            VpnRuntimeState.failed(error.message ?: error.javaClass.simpleName)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private suspend fun stopRuntime(stopService: Boolean) = lifecycleMutex.withLock {
        VpnRuntimeState.stopping()
        closeResources()
        VpnRuntimeState.disconnected()
        stopForeground(STOP_FOREGROUND_REMOVE)
        if (stopService) stopSelf()
    }

    private fun closeResources() {
        controlLoopJob?.cancel()
        controlLoopJob = null
        if (RuntimeBridge.control === this) RuntimeBridge.control = null
        commandMonitor?.close()
        commandMonitor = null
        commandServer?.let { server ->
            runCatching { server.closeService() }
            runCatching { server.close() }
        }
        commandServer = null
        tunDescriptor?.close()
        tunDescriptor = null
        restoredSelectionGroups.clear()
        if (::platform.isInitialized) platform.stop()
    }

    private fun closeCore() {
        commandMonitor?.close()
        commandMonitor = null
        commandServer?.let { server ->
            runCatching { server.closeService() }
            runCatching { server.close() }
        }
        commandServer = null
        tunDescriptor?.close()
        tunDescriptor = null
        restoredSelectionGroups.clear()
    }

    private fun startCore(config: ManagedConfig) {
        io.nekohasekai.libbox.Libbox.checkConfig(config.content)
        val server = CommandServer(this, platform)
        server.start()
        try {
            server.startOrReloadService(config.content, OverrideOptions())
        } catch (error: Throwable) {
            runCatching { server.close() }
            throw error
        }
        commandServer = server
        commandMonitor = LibboxCommandMonitor(::restoreRememberedSelections).also { it.connect() }
    }

    private fun startControlLoop() {
        if (controlLoopJob?.isActive == true) return
        controlLoopJob = serviceScope.launch {
            var iteration = 0
            while (currentCoroutineContext().isActive) {
                runCatching {
                    CoreGraph.repository.runControlCycle(
                        appVersion = applicationVersion(),
                        coreVersion = io.nekohasekai.libbox.Libbox.version(),
                    )
                }.onFailure { Log.w(TAG, "control cycle failed", it) }
                if (iteration++ % 2 == 0) {
                    runCatching { CoreGraph.repository.reportTelemetry() }
                        .onFailure { Log.w(TAG, "telemetry report failed", it) }
                }
                delay(10_000)
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun applicationVersion(): String =
        packageManager.getPackageInfo(packageName, 0).versionName ?: "unknown"

    override fun serviceStop() {
        serviceScope.launch { stopRuntime(stopService = true) }
    }

    override fun serviceReload() {
        serviceScope.launch {
            runCatching { CoreGraph.repository.syncConfiguration(force = true) }
                .onFailure { VpnRuntimeState.runtimeWarning(it.message.orEmpty()) }
        }
    }

    override suspend fun applyConfiguration(config: ManagedConfig) {
        lifecycleMutex.withLock {
            io.nekohasekai.libbox.Libbox.checkConfig(config.content)
            val server = requireNotNull(commandServer) { "VPN 未运行" }
            val previous = CoreGraph.repository.activeConfig()
            try {
                server.startOrReloadService(config.content, OverrideOptions())
            } catch (error: Throwable) {
                if (previous != null) {
                    runCatching { server.startOrReloadService(previous.content, OverrideOptions()) }
                }
                throw error
            }
            VpnRuntimeState.configurationChanged(config)
            startForegroundNotification("${config.profileName} · 配置已更新")
        }
    }

    override suspend fun restart() {
        lifecycleMutex.withLock {
            val config = requireNotNull(CoreGraph.repository.activeConfig()) { "没有可恢复的配置" }
            closeCore()
            startCore(config)
            RuntimeBridge.control = this
            VpnRuntimeState.connected(config)
            startForegroundNotification("${config.profileName} · 已重新启动")
        }
    }

    override suspend fun selectOutbound(groupTag: String, outboundTag: String) {
        commandMonitor?.selectOutbound(groupTag, outboundTag) ?: error("VPN 未运行")
        getSharedPreferences(SELECTION_PREFERENCES, MODE_PRIVATE)
            .edit()
            .putString(groupTag, outboundTag)
            .apply()
    }

    override suspend fun urlTest(groupTag: String) {
        commandMonitor?.urlTest(groupTag) ?: error("VPN 未运行")
    }

    override suspend fun clearLogs() {
        commandMonitor?.clearRuntimeLogs()
    }

    override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus().apply {
        available = false
        enabled = false
    }

    override fun setSystemProxyEnabled(enabled: Boolean) = Unit

    override fun writeDebugMessage(message: String?) {
        Log.d(TAG, message.orEmpty())
    }

    private fun restoreRememberedSelections(groups: List<ProxyGroupSnapshot>) {
        val preferences = getSharedPreferences(SELECTION_PREFERENCES, MODE_PRIVATE)
        groups.filter { it.selectable }.forEach { group ->
            if (!restoredSelectionGroups.add(group.tag)) return@forEach
            val remembered = preferences.getString(group.tag, null) ?: return@forEach
            if (remembered == group.selected || group.items.none { it.tag == remembered }) return@forEach
            serviceScope.launch {
                runCatching { commandMonitor?.selectOutbound(group.tag, remembered) }
                    .onSuccess { RuntimeObservability.markSelection(group.tag, remembered) }
                    .onFailure { Log.w(TAG, "Failed to restore ${group.tag} selection", it) }
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL,
                "sb-easy VPN",
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
    }

    private fun startForegroundNotification(text: String) {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val contentIntent = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        }
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, SbEasyVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("sb-easy Android")
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(contentIntent)
            .addAction(0, "停止", stopIntent)
            .build()

        val foregroundType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification, foregroundType)
    }

    companion object {
        const val ACTION_START = "io.sbeasy.android.action.START_VPN"
        const val ACTION_STOP = "io.sbeasy.android.action.STOP_VPN"
        private const val TAG = "SbEasyVpnService"
        private const val NOTIFICATION_CHANNEL = "sb_easy_vpn"
        private const val NOTIFICATION_ID = 51822
        private const val SELECTION_PREFERENCES = "sb_easy_proxy_selections"
    }
}
