/* SPDX-License-Identifier: GPL-3.0-or-later */
package io.sbeasy.android.libbox

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.IntentFilter
import android.os.PowerManager
import android.os.SystemClock
import androidx.core.content.ContextCompat
import io.sbeasy.android.core.ConnectivityProbe
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.TimeoutCancellationException
import android.content.pm.ServiceInfo
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
import io.sbeasy.android.core.ClientDiagnostics
import io.sbeasy.android.core.CoreGraph
import io.sbeasy.android.core.ManagedConfig
import io.sbeasy.android.core.ProxyGroupSnapshot
import io.sbeasy.android.core.RuntimeBridge
import io.sbeasy.android.core.RuntimeControl
import io.sbeasy.android.core.RuntimeLog
import io.sbeasy.android.core.RuntimeObservability
import kotlinx.coroutines.CancellationException
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
    @Volatile private var commandServer: CommandServer? = null
    private var commandMonitor: LibboxCommandMonitor? = null
    private val restoredSelectionGroups = mutableSetOf<String>()
    private var controlLoopJob: Job? = null
    private var networkHealthJob: Job? = null
    private val healthSignals = Channel<Unit>(Channel.CONFLATED)
    private val connectivityProbe = ConnectivityProbe()
    private val recoveryPolicy = BackgroundRecoveryPolicy()
    private lateinit var handoverWakeLock: PowerManager.WakeLock
    private var powerReceiverRegistered = false
    private val powerReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            ClientDiagnostics.info(TAG, "power event=${intent?.action} ${powerState()}")
            healthSignals.trySend(Unit)
        }
    }
    @Volatile private var recoveryEpoch = 0L
    @Volatile private var runtimeWanted = false
    @Volatile private var appliedNetwork: UnderlyingNetwork? = null
    @Volatile private var rebuildRequestedFor: UnderlyingNetwork? = null
    private val handover = NetworkHandover(serviceScope, onPendingChanged = { pending ->
        if (pending) recoveryEpoch++ else healthSignals.trySend(Unit)
        if (::handoverWakeLock.isInitialized) {
            if (pending) handoverWakeLock.acquire(45_000)
            else if (handoverWakeLock.isHeld) handoverWakeLock.release()
        }
    }) { network, isCurrent ->
        recoverNetwork(network, isCurrent)
    }
    private var tunDescriptor: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        LibboxInitializer.initialize(this)
        platform = AndroidPlatformBridge(this)
        createNotificationChannel()
        handoverWakeLock = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "sb-easy:handover")
            .apply { setReferenceCounted(false) }
        ContextCompat.registerReceiver(this, powerReceiver, IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
            addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
        }, ContextCompat.RECEIVER_NOT_EXPORTED)
        powerReceiverRegistered = true
        ClientDiagnostics.info(TAG, "VPN service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            runtimeWanted = false
            handover.close()
            ClientDiagnostics.info(TAG, "stop requested")
            serviceScope.launch { stopRuntime(stopService = true) }
            return Service.START_NOT_STICKY
        }

        runtimeWanted = true
        startForegroundNotification("正在同步受管配置")
        ClientDiagnostics.info(TAG, "start requested")
        serviceScope.launch { startRuntime() }
        return Service.START_STICKY
    }

    override fun onBind(intent: Intent): IBinder? = super.onBind(intent)

    override fun onRevoke() {
        runtimeWanted = false
        handover.close()
        serviceScope.launch { stopRuntime(stopService = true) }
    }

    override fun onDestroy() {
        runtimeWanted = false
        handover.close()
        runBlocking(Dispatchers.IO) { lifecycleMutex.withLock { closeResources() } }
        serviceScope.cancel()
        if (powerReceiverRegistered) { unregisterReceiver(powerReceiver); powerReceiverRegistered = false }
        healthSignals.close()
        super.onDestroy()
    }

    internal fun attachTun(descriptor: ParcelFileDescriptor) {
        tunDescriptor?.close()
        tunDescriptor = descriptor
    }

    internal fun onUnderlyingNetworkChanged(network: UnderlyingNetwork?) {
        if (!runtimeWanted) return
        rebuildRequestedFor = null
        handover.changed(network)
        healthSignals.trySend(Unit)
        ClientDiagnostics.info(TAG, "handover callback ${powerState()}")
        if (network == null) {
            appliedNetwork = null
            ClientDiagnostics.warn(TAG, "no usable underlying network; pending handover canceled")
            VpnRuntimeState.runtimeWarning("底层网络不可用，等待网络恢复")
            startForegroundNotification("等待网络恢复")
        }
    }

    private suspend fun recoverNetwork(network: UnderlyingNetwork, isCurrent: () -> Boolean): Boolean {
        val recovered = lifecycleMutex.withLock {
            if (!runtimeWanted || !isCurrent()) return@withLock true
            val config = CoreGraph.repository.activeConfig() ?: return@withLock false
            if (commandServer != null && appliedNetwork == network && rebuildRequestedFor != network) return@withLock true
            ClientDiagnostics.info(TAG, "recovering libbox network=${network.handle} interface=${network.interfaceName}")
            try {
                val result = recoverCoreNetwork(
                    hasCore = commandServer != null,
                    rebuildRequired = rebuildRequestedFor == network,
                    isCurrent = { runtimeWanted && isCurrent() },
                    reset = { requireNotNull(commandServer).resetNetwork() },
                    rebuild = { closeCore(); startCore(config) },
                    onResetFailure = { ClientDiagnostics.error(TAG, "network reset failed; rebuilding core", it) },
                )
                if (result == NetworkRecoveryResult.OBSOLETE) return@withLock true
                ClientDiagnostics.info(TAG, "network recovery action=$result network=${network.handle}")
                rebuildRequestedFor = null
                appliedNetwork = network
                RuntimeBridge.control = this@SbEasyVpnService
                VpnRuntimeState.connected(config)
                VpnRuntimeState.runtimeWarning("网络状态已更新，正在验证连接")
                startForegroundNotification("正在验证切换后的网络")
                true
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                appliedNetwork = null
                ClientDiagnostics.error(TAG, "network recovery failed; will retry", error)
                VpnRuntimeState.failed(error.message ?: error.javaClass.simpleName)
                startForegroundNotification("网络恢复失败，等待重试")
                false
            }
        }
        if (recovered && runtimeWanted && isCurrent()) healthSignals.trySend(Unit)
        return recovered
    }

    private suspend fun startRuntime() {
        try {
            runCatching { CoreGraph.repository.syncConfiguration() }
            val config = requireNotNull(CoreGraph.repository.activeConfig()) {
                "尚未取得可用配置，请先在 App 中完成设备注册"
            }
            lifecycleMutex.withLock {
                if (!runtimeWanted || commandServer != null) return
                VpnRuntimeState.starting()
                ClientDiagnostics.info(TAG, "starting libbox runtime")
                platform.start()
                startCore(config)
                appliedNetwork = platform.underlyingNetwork
                RuntimeBridge.control = this
                VpnRuntimeState.connected(config)
                startForegroundNotification("${config.profileName} · 代理运行中")
                startControlLoop()
                startNetworkWatchdog()
                ClientDiagnostics.info(TAG, "libbox runtime connected profile=${config.profileName}")
            }
        } catch (error: Throwable) {
            Log.e(TAG, "Failed to start libbox", error)
            ClientDiagnostics.error(TAG, "failed to start libbox", error)
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
        runtimeWanted = false
        handover.close()
        networkHealthJob?.cancel()
        networkHealthJob = null
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
        appliedNetwork = null
        rebuildRequestedFor = null
        ClientDiagnostics.info(TAG, "VPN runtime resources closed")
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
        val inbounds = org.json.JSONObject(config.content).optJSONArray("inbounds")
        val stacks = (0 until (inbounds?.length() ?: 0)).mapNotNull { index ->
            inbounds?.optJSONObject(index)?.takeIf { it.optString("type") == "tun" }?.optString("stack", "default")
        }
        ClientDiagnostics.info(TAG, "starting core tunStacks=$stacks")
        val server = CommandServer(this, platform)
        server.start()
        try {
            server.startOrReloadService(config.content, OverrideOptions())
            restoreLocalDefaults(config)
        } catch (error: Throwable) {
            runCatching { server.closeService() }
            runCatching { server.close() }
            throw error
        }
        commandServer = server
        commandMonitor = LibboxCommandMonitor(::restoreRememberedSelections).also { it.connect() }
    }

    private fun restoreLocalDefaults(config: ManagedConfig) {
        // The core caches selector choices as well as rule sets. Restore our
        // authoritative local policy synchronously before reporting connected;
        // keeping the cache namespace preserves rule sets for offline startup.
        val client = io.nekohasekai.libbox.Libbox.newStandaloneCommandClient()
        try {
            io.sbeasy.android.core.LocalRouting.selectionsFromConfig(config.content).forEach { (tag, selected) ->
                client.selectOutbound(tag, selected)
            }
        } finally {
            runCatching { client.disconnect() }
        }
    }

    private fun powerState(): String {
        val power = getSystemService(PowerManager::class.java)
        return "interactive=${power.isInteractive} idle=${power.isDeviceIdleMode} " +
            "powerSave=${power.isPowerSaveMode} batteryExempt=${power.isIgnoringBatteryOptimizations(packageName)}"
    }

    /** Owned by the foreground VPN service; never depends on an Activity collector. */
    private fun startNetworkWatchdog() {
        if (networkHealthJob?.isActive == true) return
        networkHealthJob = serviceScope.launch {
            healthSignals.trySend(Unit)
            var lastCheckFinished: Long? = null
            while (currentCoroutineContext().isActive && runtimeWanted) {
                withTimeoutOrNull(30_000) { healthSignals.receive() }
                if (!runtimeWanted) break
                // Handover completion and screen-on can arrive together. Do not
                // turn those notifications into back-to-back failed samples.
                if (lastCheckFinished?.let { SystemClock.elapsedRealtime() - it < 15_000 } == true) continue
                val wakeLock = getSystemService(PowerManager::class.java)
                    .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "sb-easy:health-check")
                wakeLock.acquire(25_000)
                try {
                    platform.reconcileNetworks()
                    val network = platform.underlyingNetwork
                    if (network == null) {
                        recoveryPolicy.record(null, false, SystemClock.elapsedRealtime())
                        continue
                    }
                    if (handover.pending) continue
                    val epoch = recoveryEpoch
                    val config = CoreGraph.repository.activeConfig() ?: continue
                    val started = SystemClock.elapsedRealtime()
                    val outbounds = org.json.JSONObject(config.content).optJSONArray("outbounds")
                    val url = (0 until (outbounds?.length() ?: 0)).asSequence()
                        .mapNotNull { outbounds?.optJSONObject(it) }
                        .firstOrNull { it.optString("type") == "urltest" }
                        ?.optString("url")?.takeIf { it.isNotBlank() }
                    var failure: String? = null
                    var reachedHost: String? = null
                    val healthy = if (appliedNetwork != network || commandServer == null) false else try {
                        if (url != null) {
                            val result = connectivityProbe.checkAny(listOf(url, "https://cp.cloudflare.com/generate_204"))
                            reachedHost = result.reachedHost
                            failure = result.failures.takeIf { it.isNotEmpty() }?.joinToString("; ")
                            result.healthy
                        } else true
                    } catch (error: TimeoutCancellationException) {
                        failure = "connectivity probe exceeded 10s deadline"
                        false
                    } catch (error: CancellationException) {
                        throw error
                    } catch (error: Exception) {
                        failure = error.message ?: error.javaClass.simpleName
                        false
                    }
                    // Never apply a result for a network that disappeared during the request.
                    if (!runtimeWanted || platform.underlyingNetwork != network || recoveryEpoch != epoch) continue
                    lastCheckFinished = SystemClock.elapsedRealtime()
                    ClientDiagnostics.info(TAG, "background health network=${network.handle} ok=$healthy " +
                        "probe=${url != null} elapsedMs=${SystemClock.elapsedRealtime() - started} " +
                        "reached=$reachedHost error=$failure ${powerState()}")
                    if (healthy) {
                        VpnRuntimeState.connected(config)
                        startForegroundNotification(if (url == null) "代理运行中（未配置检测地址）" else "${config.profileName} · 网络已恢复")
                    } else {
                        VpnRuntimeState.runtimeWarning("连接检测未通过，请检查当前节点或网络")
                        startForegroundNotification("连接检测未通过 · 保留现有连接")
                    }
                    if (recoveryPolicy.record(network, healthy, SystemClock.elapsedRealtime())) {
                        ClientDiagnostics.warn(TAG, "sustained probe failure; one core rebuild for this outage network=${network.handle}")
                        VpnRuntimeState.runtimeWarning("连接持续异常，正在尝试一次自动恢复")
                        startForegroundNotification("连接持续异常 · 正在恢复")
                        rebuildRequestedFor = network
                        appliedNetwork = null
                        handover.changed(network, force = true)
                    }
                } catch (error: CancellationException) {
                    throw error
                } catch (error: Exception) {
                    ClientDiagnostics.error(TAG, "background watchdog check failed", error)
                } finally {
                    if (wakeLock.isHeld) wakeLock.release()
                }
            }
        }
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
                restoreLocalDefaults(config)
                restoredSelectionGroups.clear()
            } catch (error: Throwable) {
                if (previous != null) {
                    runCatching {
                        server.startOrReloadService(previous.content, OverrideOptions())
                        restoreLocalDefaults(previous)
                    }
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
        message?.takeIf { it.isNotBlank() }?.let {
            ClientDiagnostics.appendLibbox(listOf(RuntimeLog(ClientDiagnostics.INFO, it)))
        }
    }

    private fun restoreRememberedSelections(groups: List<ProxyGroupSnapshot>) {
        val preferences = getSharedPreferences(SELECTION_PREFERENCES, MODE_PRIVATE)
        groups.filter { it.selectable }.forEach { group ->
            // Device-owned groups get their authoritative defaults from the
            // local routing policy, including changes made while disconnected.
            if (group.tag.startsWith(io.sbeasy.android.core.LocalRouting.TAG_PREFIX)) return@forEach
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
