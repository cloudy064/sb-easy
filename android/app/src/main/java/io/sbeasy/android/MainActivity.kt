package io.sbeasy.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import io.sbeasy.android.core.ConfigInspector
import io.sbeasy.android.core.ClientDiagnostics
import io.sbeasy.android.core.ControlPlaneSnapshot
import io.sbeasy.android.core.CoreGraph
import io.sbeasy.android.core.DomainRouteStat
import io.sbeasy.android.core.EnrollmentUriParser
import io.sbeasy.android.core.ManagedConfig
import io.sbeasy.android.core.LocalRouting
import io.sbeasy.android.core.LocalRoutingGroup
import io.sbeasy.android.core.LocalRoutingPolicy
import io.sbeasy.android.core.LocalRoutingSnapshot
import io.sbeasy.android.core.ProxyGroupSnapshot
import io.sbeasy.android.core.RouteDecision
import io.sbeasy.android.core.RouteTestResult
import io.sbeasy.android.core.RuntimeLog
import io.sbeasy.android.core.RuntimeObservability
import io.sbeasy.android.core.SyncPhase
import io.sbeasy.android.core.TrafficSnapshot
import io.sbeasy.android.core.VpnPhase
import io.sbeasy.android.core.VpnRuntimeState
import io.sbeasy.android.libbox.SbEasyVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val incomingEnrollment = mutableStateOf<String?>(null)
    private var pendingScanResult: ((String) -> Unit)? = null
    private var pendingScanError: ((String) -> Unit)? = null

    private val cameraScanner = registerForActivityResult(ScanContract()) { result ->
        val value = result.contents
        if (!value.isNullOrBlank()) deliverScannedEnrollment(value)
        clearScanCallbacks()
    }

    private val imagePicker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null) {
            clearScanCallbacks()
            return@registerForActivityResult
        }
        decodeEnrollmentImage(uri)
    }

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result -> if (result.resultCode == Activity.RESULT_OK) startVpnService() }

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ClientDiagnostics.info("MainActivity", "activity created app=${BuildConfig.VERSION_NAME}")
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
        )
        acceptEnrollmentIntent(intent)
        setContent {
            SbEasyApp(
                initialEnrollmentUri = incomingEnrollment.value,
                onEnrollmentConsumed = { incomingEnrollment.value = null },
                onScan = ::scanEnrollment,
                onPickImage = ::pickEnrollmentImage,
                onConnect = ::requestVpn,
                onDisconnect = ::stopVpnService,
            )
        }
    }

    override fun onResume() {
        super.onResume()
        val power = getSystemService(android.os.PowerManager::class.java)
        ClientDiagnostics.info("MainActivity", "activity resumed interactive=${power.isInteractive} idle=${power.isDeviceIdleMode} batteryExempt=${power.isIgnoringBatteryOptimizations(packageName)}")
    }

    override fun onPause() {
        ClientDiagnostics.info("MainActivity", "activity paused")
        super.onPause()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        acceptEnrollmentIntent(intent)
    }

    private fun acceptEnrollmentIntent(intent: Intent?) {
        intent?.data?.toString()?.takeIf { it.startsWith("sbeasy://enroll") }?.let {
            incomingEnrollment.value = it
        }
    }

    private fun scanEnrollment(onResult: (String) -> Unit, onError: (String) -> Unit) {
        pendingScanResult = onResult
        pendingScanError = onError
        cameraScanner.launch(
            ScanOptions()
                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                .setPrompt("将 sb-easy 注册二维码放入取景框")
                .setBeepEnabled(false)
                .setOrientationLocked(false),
        )
    }

    private fun pickEnrollmentImage(onResult: (String) -> Unit, onError: (String) -> Unit) {
        pendingScanResult = onResult
        pendingScanError = onError
        imagePicker.launch("image/*")
    }

    private fun decodeEnrollmentImage(uri: Uri) {
        lifecycleScope.launch(Dispatchers.Default) {
            val decoded = runCatching { decodeQrCode(uri) }
            withContext(Dispatchers.Main) {
                decoded.onSuccess(::deliverScannedEnrollment).onFailure {
                    pendingScanError?.invoke(
                        it.message ?: "图片中未识别到注册二维码，请选择清晰的原图或截图",
                    )
                }
                clearScanCallbacks()
            }
        }
    }

    private fun deliverScannedEnrollment(value: String) {
        runCatching { EnrollmentUriParser.parse(value) }
            .onSuccess { pendingScanResult?.invoke(value.trim()) }
            .onFailure {
                pendingScanError?.invoke(it.message ?: "二维码不是有效的 sb-easy 注册链接")
            }
    }

    private fun clearScanCallbacks() {
        pendingScanResult = null
        pendingScanError = null
    }

    private fun decodeQrCode(uri: Uri): String {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        val boundsStream = contentResolver.openInputStream(uri)
            ?: error("无法读取所选图片")
        boundsStream.use { BitmapFactory.decodeStream(it, null, bounds) }
        require(bounds.outWidth > 0 && bounds.outHeight > 0) { "所选文件不是有效图片" }

        var sampleSize = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / sampleSize > 2_048) {
            sampleSize *= 2
        }
        val options = BitmapFactory.Options().apply {
            inSampleSize = sampleSize
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val bitmap = contentResolver.openInputStream(uri)?.use {
            BitmapFactory.decodeStream(it, null, options)
        } ?: error("无法解码所选图片")
        return try {
            decodeQrCode(bitmap)
        } finally {
            bitmap.recycle()
        }
    }

    private fun decodeQrCode(bitmap: Bitmap): String {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        return QrCodeDecoder.decode(bitmap.width, bitmap.height, pixels)
    }

    private fun requestVpn() {
        ClientDiagnostics.info("MainActivity", "VPN permission/start requested")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)

        val intent = VpnService.prepare(this)
        if (intent == null) startVpnService() else vpnPermission.launch(intent)
    }

    private fun startVpnService() {
        ClientDiagnostics.info("MainActivity", "starting foreground VPN service")
        ContextCompat.startForegroundService(
            this,
            Intent(this, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_START),
        )
    }

    private fun stopVpnService() {
        ClientDiagnostics.info("MainActivity", "stopping VPN service")
        startService(Intent(this, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_STOP))
    }
}

private val Background = Color(0xFF090E13)
private val SurfaceColor = Color(0xFF111920)
private val SurfaceRaised = Color(0xFF172129)
private val Ink = Color(0xFFEAF4F0)
private val Muted = Color(0xFF8FA39B)
private val Line = Color(0xFF26343A)
private val Accent = Color(0xFF43D7A3)
private val AccentDark = Color(0xFF83E9C5)
private val AccentSoft = Color(0xFF16362E)
private val Danger = Color(0xFFFF7D83)
private val Warn = Color(0xFFFFC875)
private val CodeBackground = Color(0xFF060A0E)

@Composable
private fun SbEasyApp(
    initialEnrollmentUri: String?,
    onEnrollmentConsumed: () -> Unit,
    onScan: ((String) -> Unit, (String) -> Unit) -> Unit,
    onPickImage: ((String) -> Unit, (String) -> Unit) -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val control by CoreGraph.repository.state.collectAsStateWithLifecycle()
    val vpn by VpnRuntimeState.state.collectAsStateWithLifecycle()
    val traffic by RuntimeObservability.traffic.collectAsStateWithLifecycle()
    val groups by RuntimeObservability.groups.collectAsStateWithLifecycle()
    val connections by RuntimeObservability.connections.collectAsStateWithLifecycle()
    val domainRoutes by RuntimeObservability.domainRoutes.collectAsStateWithLifecycle()
    val logs by RuntimeObservability.logs.collectAsStateWithLifecycle()
    val diagnosticLogs by ClientDiagnostics.entries.collectAsStateWithLifecycle()
    val routing by CoreGraph.repository.routing.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var selectedTab by remember { mutableIntStateOf(0) }
    var actionError by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(control.enrollment?.hostId) {
        if (control.enrollment != null && vpn.phase != VpnPhase.CONNECTED) {
            runCatching { CoreGraph.repository.syncConfiguration() }
        }
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Accent,
            secondary = Accent,
            background = Background,
            surface = SurfaceColor,
            error = Danger,
            onPrimary = Color.White,
            onBackground = Ink,
            onSurface = Ink,
        ),
    ) {
        Surface(
            color = Background,
            modifier = Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).imePadding(),
        ) {
            if (control.enrollment == null) {
                EnrollmentScreen(
                    initialUri = initialEnrollmentUri,
                    coreVersion = vpn.coreVersion.orEmpty(),
                    onConsumed = onEnrollmentConsumed,
                    onScan = onScan,
                    onPickImage = onPickImage,
                    onEnroll = { uri ->
                        scope.launch {
                            actionError = null
                            runCatching {
                                CoreGraph.repository.enroll(uri, BuildConfig.VERSION_NAME, vpn.coreVersion.orEmpty())
                            }.onFailure { actionError = it.message ?: "注册失败" }
                        }
                    },
                    syncing = control.syncPhase == SyncPhase.SYNCING,
                    error = actionError ?: control.lastError,
                )
                return@Surface
            }

            AppShell(
                selectedTab = selectedTab,
                onSelectTab = { selectedTab = it },
                header = { AppHeader(control, vpn.phase) },
            ) {
                when (selectedTab) {
                    0 -> HomeScreen(control, vpn.phase, vpn.detail, vpn.error, traffic, groups, routing, onConnect, onDisconnect)
                    1 -> ProxiesScreen(groups, routing, vpn.phase)
                    2 -> ToolsScreen(control.config, connections.size, domainRoutes, logs, diagnosticLogs, vpn.phase, vpn.coreVersion)
                    else -> SettingsScreen(control, vpn.coreVersion, vpn.phase, onDisconnect)
                }
            }
        }
    }
}

private val destinations = listOf("总览", "代理", "诊断", "设置")

@Composable
private fun AppShell(
    selectedTab: Int,
    onSelectTab: (Int) -> Unit,
    header: @Composable () -> Unit,
    content: @Composable () -> Unit,
) {
    BoxWithConstraints(Modifier.fillMaxSize()) {
        if (maxWidth >= 720.dp) {
            Row(Modifier.fillMaxSize()) {
                Column(
                    modifier = Modifier.width(190.dp).fillMaxHeight().background(SurfaceColor).padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text("SB / EASY", color = AccentDark, fontWeight = FontWeight.Black, fontSize = 15.sp, modifier = Modifier.padding(12.dp))
                    destinations.forEachIndexed { index, label ->
                        Text(
                            label,
                            color = if (selectedTab == index) AccentDark else Muted,
                            fontWeight = if (selectedTab == index) FontWeight.Bold else FontWeight.Medium,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(12.dp))
                                .background(if (selectedTab == index) AccentSoft else Color.Transparent)
                                .clickable { onSelectTab(index) }
                                .padding(horizontal = 14.dp, vertical = 13.dp),
                        )
                    }
                }
                Column(Modifier.weight(1f).fillMaxHeight()) {
                    header()
                    Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                        Box(Modifier.widthIn(max = 960.dp).fillMaxWidth().fillMaxHeight()) { content() }
                    }
                }
            }
        } else {
            Scaffold(
                containerColor = Background,
                topBar = header,
                bottomBar = { CompactNavigation(selectedTab, onSelectTab) },
                contentWindowInsets = WindowInsets(0, 0, 0, 0),
            ) { padding ->
                Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.TopCenter) {
                    Box(Modifier.widthIn(max = 960.dp).fillMaxWidth().fillMaxHeight()) { content() }
                }
            }
        }
    }
}

@Composable
private fun CompactNavigation(selectedTab: Int, onSelectTab: (Int) -> Unit) {
    NavigationBar(containerColor = SurfaceColor, tonalElevation = 0.dp, windowInsets = WindowInsets(0, 0, 0, 0)) {
        destinations.forEachIndexed { index, label ->
            NavigationBarItem(
                selected = selectedTab == index,
                onClick = { onSelectTab(index) },
                icon = {
                    Box(
                        Modifier
                            .size(if (selectedTab == index) 7.dp else 5.dp)
                            .clip(CircleShape)
                            .background(if (selectedTab == index) Accent else Muted),
                    )
                },
                label = { Text(label, fontSize = 11.sp) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Accent,
                    selectedTextColor = AccentDark,
                    indicatorColor = AccentSoft,
                    unselectedIconColor = Muted,
                    unselectedTextColor = Muted,
                ),
            )
        }
    }
}

@Composable
private fun AppHeader(control: ControlPlaneSnapshot, vpnPhase: VpnPhase) {
    Row(
        modifier = Modifier.fillMaxWidth().background(SurfaceColor).padding(horizontal = 18.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier.size(36.dp).clip(RoundedCornerShape(11.dp)).background(Accent),
            contentAlignment = Alignment.Center,
        ) { Text("S", color = Color.White, fontWeight = FontWeight.Black, fontSize = 18.sp) }
        Column(Modifier.padding(start = 10.dp)) {
            Text("sb-easy", color = Ink, fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Text(control.enrollment?.hostName.orEmpty(), color = Muted, fontSize = 11.sp)
        }
        Spacer(Modifier.weight(1f))
        StatusChip(vpnPhase == VpnPhase.CONNECTED, if (vpnPhase == VpnPhase.CONNECTED) "已连接" else "未连接")
    }
}

@Composable
private fun EnrollmentScreen(
    initialUri: String?,
    coreVersion: String,
    onConsumed: () -> Unit,
    onScan: ((String) -> Unit, (String) -> Unit) -> Unit,
    onPickImage: ((String) -> Unit, (String) -> Unit) -> Unit,
    onEnroll: (String) -> Unit,
    syncing: Boolean,
    error: String?,
) {
    var value by remember { mutableStateOf("") }
    var scanError by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(initialUri) {
        if (!initialUri.isNullOrBlank()) {
            value = initialUri
            onConsumed()
        }
    }
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier.widthIn(max = 560.dp).fillMaxWidth().fillMaxHeight().verticalScroll(rememberScrollState()).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(38.dp))
            Box(Modifier.size(68.dp).clip(RoundedCornerShape(22.dp)).background(Accent), contentAlignment = Alignment.Center) {
                Text("S", color = Color.White, fontSize = 34.sp, fontWeight = FontWeight.Black)
            }
            Text("连接到 sb-easy", color = Ink, fontSize = 26.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 22.dp))
            Text("扫描管理端生成的一次性二维码，把这台手机加入你的代理网络。", color = Muted, fontSize = 14.sp, lineHeight = 21.sp, modifier = Modifier.padding(top = 8.dp))
            Spacer(Modifier.height(28.dp))
            AppCard {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(
                        onClick = { onScan({ value = it; scanError = null }, { scanError = it }) },
                        modifier = Modifier.weight(1f).height(52.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Color.White),
                        shape = RoundedCornerShape(14.dp),
                    ) { Text("相机扫码", fontWeight = FontWeight.SemiBold) }
                    OutlinedButton(
                        onClick = { onPickImage({ value = it; scanError = null }, { scanError = it }) },
                        modifier = Modifier.weight(1f).height(52.dp),
                        shape = RoundedCornerShape(14.dp),
                    ) { Text("从相册选择", fontWeight = FontWeight.SemiBold) }
                }
                Row(Modifier.fillMaxWidth().padding(vertical = 18.dp), verticalAlignment = Alignment.CenterVertically) {
                    HorizontalDivider(Modifier.weight(1f), color = Line)
                    Text("或手动粘贴", color = Muted, fontSize = 11.sp, modifier = Modifier.padding(horizontal = 10.dp))
                    HorizontalDivider(Modifier.weight(1f), color = Line)
                }
                OutlinedTextField(
                    value = value,
                    onValueChange = { value = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("sbeasy:// 注册链接") },
                    minLines = 3,
                    shape = RoundedCornerShape(14.dp),
                )
                Button(
                    onClick = { onEnroll(value) },
                    enabled = value.isNotBlank() && !syncing,
                    modifier = Modifier.fillMaxWidth().padding(top = 14.dp),
                    shape = RoundedCornerShape(14.dp),
                ) {
                    if (syncing) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = Color.White)
                    else Text("注册并同步配置")
                }
                (scanError ?: error)?.let { ErrorText(it) }
            }
            Text("凭据由 Android Keystore 加密 · sing-box $coreVersion", color = Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 18.dp))
        }
    }
}

@Composable
private fun HomeScreen(
    control: ControlPlaneSnapshot,
    phase: VpnPhase,
    detail: String,
    runtimeError: String?,
    traffic: TrafficSnapshot,
    groups: List<ProxyGroupSnapshot>,
    routing: LocalRoutingSnapshot,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val connected = phase == VpnPhase.CONNECTED
    val busy = phase == VpnPhase.STARTING || phase == VpnPhase.STOPPING
    val selectedProxy = groups.firstOrNull { it.tag == routing.defaultTag && it.selected.isNotBlank() }?.selected
        ?: routing.selections[routing.defaultTag]
        ?: "等待代理组数据"
    LazyColumn(contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = SurfaceRaised),
                shape = RoundedCornerShape(22.dp),
                border = BorderStroke(1.dp, if (connected) Color(0xFF2C745F) else Line),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(20.dp)) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(if (connected) "网络已受保护" else detail, color = Ink, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                            Text(selectedProxy, color = if (connected) AccentDark else Muted, fontSize = 13.sp, modifier = Modifier.padding(top = 5.dp))
                        }
                        StatusChip(connected, if (connected) "运行中" else "已停止")
                    }
                    Button(
                        onClick = if (connected) onDisconnect else onConnect,
                        enabled = !busy && control.config != null,
                        modifier = Modifier.padding(top = 14.dp).fillMaxWidth().height(52.dp),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (connected) Color(0xFF26343A) else Accent,
                            contentColor = if (connected) Ink else Color(0xFF052018),
                        ),
                    ) { Text(if (busy) "正在处理…" else if (connected) "断开 VPN" else "启动 VPN", fontSize = 15.sp, fontWeight = FontWeight.Bold) }
                    if (control.config == null) Text("先同步配置后才能连接", color = Warn, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp))
                }
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                StatCard("↑ 上传", formatRate(traffic.uplink), Modifier.weight(1f))
                StatCard("↓ 下载", formatRate(traffic.downlink), Modifier.weight(1f))
            }
        }
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
                StatCard("活动连接", (traffic.connectionsIn + traffic.connectionsOut).toString(), Modifier.weight(1f))
                StatCard("累计流量", formatBytes(traffic.uplinkTotal + traffic.downlinkTotal), Modifier.weight(1f))
            }
        }
        item {
            AppCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("运行配置", color = Ink, fontWeight = FontWeight.SemiBold)
                        Text(control.config?.profileName ?: "尚未同步", color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 3.dp))
                    }
                    SourceBadge(control.config?.ruleSource)
                }
                HorizontalDivider(Modifier.padding(vertical = 14.dp), color = Line)
                InfoRow("配置版本", shortEtag(control.config?.etag))
                InfoRow("最后同步", formatTime(control.config?.syncedAtMillis))
                TextButton(onClick = { scope.launch { runCatching { CoreGraph.repository.syncConfiguration(force = true) } } }) {
                    Text(if (control.syncPhase == SyncPhase.SYNCING) "正在同步…" else "立即同步", color = AccentDark)
                }
                control.lastError?.let { ErrorText(it) }
                runtimeError?.let { ErrorText(it) }
            }
        }
    }
}

@Composable
private fun ProxiesScreen(
    groups: List<ProxyGroupSnapshot>,
    routing: LocalRoutingSnapshot,
    phase: VpnPhase,
) {
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var testing by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var expandedTag by remember { mutableStateOf<String?>(null) }
    var editor by remember { mutableStateOf<LocalRoutingGroup?>(null) }
    var deleting by remember { mutableStateOf<LocalRoutingGroup?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    val policy = routing.policy
    if (policy == null) {
        EmptyPanel("先同步服务器配置，即可设置默认代理和服务分组")
        return
    }
    val changingVpn = phase == VpnPhase.STARTING || phase == VpnPhase.STOPPING
    val canEdit = !busy && !changingVpn
    val latencyGroup = groups.firstOrNull { it.type.equals("urltest", ignoreCase = true) }
    val latencyByTag = latencyGroup?.items?.associateBy { it.tag }.orEmpty()
    val rows = listOf(Triple(routing.defaultTag, "默认代理", null)) + policy.groups.map {
        Triple(routing.groupTags.getValue(it.id), it.name, it)
    }
    LazyColumn(contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            AppCard {
                Text("服务分组", color = Ink, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                Text("每组使用一个固定节点，国内和局域网直连，其余流量使用默认代理。",
                    color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 5.dp))
                Text("设置保存在本机，重启和服务器同步后继续生效。",
                    color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 5.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 12.dp)) {
                    Button(onClick = {
                        error = null
                        editor = LocalRoutingGroup(java.util.UUID.randomUUID().toString(), "", emptyList(),
                            routing.selections[routing.defaultTag] ?: policy.defaultOutbound)
                    }, enabled = canEdit && policy.groups.size < 32) { Text("创建分组") }
                    OutlinedButton(onClick = {
                        scope.launch {
                            val target = latencyGroup ?: return@launch
                            testing = true
                            error = null
                            message = null
                            runCatching { CoreGraph.repository.testGroup(target.tag) }
                                .onSuccess { message = "测速完成：${it.tested}/${it.total} 个节点返回结果" }
                                .onFailure { error = it.message }
                            testing = false
                        }
                    }, enabled = canEdit && !testing && phase == VpnPhase.CONNECTED && latencyGroup != null) {
                        Text(if (testing) "测速中…" else "节点测速")
                    }
                }
                if (phase != VpnPhase.CONNECTED) {
                    Text("可在未连接时设置，启动 VPN 后生效。", color = AccentDark, fontSize = 12.sp,
                        modifier = Modifier.padding(top = 9.dp))
                }
                if (busy) Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 9.dp)) {
                    CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = Accent)
                    Text("正在应用设置…", color = Muted, fontSize = 12.sp, modifier = Modifier.padding(start = 8.dp))
                }
                routing.warnings.forEach { Text(it, color = Warn, fontSize = 12.sp, modifier = Modifier.padding(top = 9.dp)) }
                message?.let { Text(it, color = AccentDark, fontSize = 12.sp, modifier = Modifier.padding(top = 9.dp)) }
                error?.let { ErrorText(it) }
            }
        }
        items(rows, key = { it.first }) { (tag, name, group) ->
            val selected = groups.firstOrNull { it.tag == tag }?.selected
                ?: routing.selections[tag].orEmpty()
            val expanded = expandedTag == tag
            AppCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(name, color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                        Text(selected.ifBlank { "尚未选择" }, color = AccentDark, fontSize = 13.sp,
                            modifier = Modifier.padding(top = 5.dp))
                    }
                    TextButton(onClick = { expandedTag = if (expanded) null else tag; query = "" }, enabled = canEdit) {
                        Text(if (expanded) "收起" else "选择节点")
                    }
                }
                if (group == null) {
                    Text("未命中服务分组且需要代理的流量", color = Muted, fontSize = 12.sp,
                        modifier = Modifier.padding(top = 8.dp))
                } else {
                    val appName = LocalRouting.officialAppName(group.id)?.takeIf { group.includeOfficialApp }
                    Text((appName?.let { "官方 $it App · " } ?: "") + "${group.domains.size} 个域名及其子域名", color = Muted, fontSize = 12.sp,
                        modifier = Modifier.padding(top = 8.dp))
                    Text(group.domains.take(3).joinToString(" · ") + if (group.domains.size > 3) " …" else "",
                        color = Muted, fontSize = 11.sp, modifier = Modifier.padding(top = 5.dp))
                    Row {
                        TextButton(onClick = { editor = group; error = null }, enabled = canEdit) { Text("编辑规则") }
                        TextButton(onClick = { deleting = group }, enabled = canEdit) { Text("删除分组", color = Danger) }
                    }
                }
                if (expanded) {
                    OutlinedTextField(value = query, onValueChange = { query = it }, label = { Text("搜索节点") },
                        singleLine = true, modifier = Modifier.fillMaxWidth().padding(top = 10.dp))
                    val visible = routing.availableNodes.filter { query.isBlank() || it.tag.contains(query.trim(), ignoreCase = true) }
                    visible.forEach { proxy ->
                        val isSelected = selected == proxy.tag
                        val latency = latencyByTag[proxy.tag] ?: proxy
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp).clip(RoundedCornerShape(13.dp))
                                .background(if (isSelected) AccentSoft else Color.Transparent)
                                .clickable(enabled = canEdit) {
                                    scope.launch {
                                        busy = true
                                        error = null
                                        message = null
                                        runCatching { CoreGraph.repository.selectOutbound(tag, proxy.tag) }
                                            .onSuccess { message = "$name 已使用 ${proxy.tag}"; expandedTag = null }
                                            .onFailure { error = it.message }
                                        busy = false
                                    }
                                }.padding(horizontal = 5.dp, vertical = 7.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = isSelected, onClick = null, enabled = canEdit)
                            Column(Modifier.weight(1f)) {
                                Text(proxy.tag, color = if (isSelected) AccentDark else Ink, fontSize = 14.sp,
                                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                    maxLines = 2, overflow = TextOverflow.Ellipsis)
                                Text(if (proxy.tag == "direct") "直接连接" else "固定节点 · ${proxy.type}",
                                    color = Muted, fontSize = 11.sp)
                            }
                            if (proxy.tag != "direct") DelayBadge(latency.urlTestDelay)
                        }
                    }
                    if (visible.isEmpty()) Text("没有匹配的节点", color = Muted, fontSize = 12.sp, modifier = Modifier.padding(12.dp))
                }
            }
        }
        item {
            AppCard {
                Text("直连", color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                Text("国内域名、国内 IP、局域网和管理服务器 → direct", color = Muted, fontSize = 12.sp,
                    modifier = Modifier.padding(top = 7.dp))
                Text("网页按域名匹配，Claude 和 GPT 组也包含官方 App 的流量。新增服务域名或第三方网关可在对应组补充。",
                    color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 7.dp))
            }
        }
    }
    editor?.let { original ->
        RoutingGroupEditor(original, policy, busy, error, onDismiss = { if (!busy) editor = null }) { updated ->
            scope.launch {
                busy = true
                error = null
                message = null
                val fresh = CoreGraph.repository.routing.value.policy ?: policy
                val next = fresh.copy(groups = if (fresh.groups.any { it.id == updated.id }) {
                    fresh.groups.map { if (it.id == updated.id) updated else it }
                } else fresh.groups + updated)
                runCatching { CoreGraph.repository.updateLocalRouting(next) }
                    .onSuccess { message = "${updated.name} 分组已保存"; editor = null }
                    .onFailure { error = it.message }
                busy = false
            }
        }
    }
    deleting?.let { group ->
        AlertDialog(onDismissRequest = { if (!busy) deleting = null },
            title = { Text("删除 ${group.name} 分组？") },
            text = { Text("该组域名将重新按直连规则或默认代理处理。") },
            dismissButton = { TextButton(onClick = { deleting = null }, enabled = !busy) { Text("取消") } },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch {
                        busy = true
                        error = null
                        val fresh = CoreGraph.repository.routing.value.policy ?: policy
                        runCatching { CoreGraph.repository.updateLocalRouting(fresh.copy(groups = fresh.groups.filterNot { it.id == group.id })) }
                            .onSuccess { message = "${group.name} 分组已删除"; deleting = null }
                            .onFailure { error = it.message }
                        busy = false
                    }
                }, enabled = !busy) { Text("删除", color = Danger) }
            })
    }
}

@Composable
private fun RoutingGroupEditor(
    original: LocalRoutingGroup,
    policy: LocalRoutingPolicy,
    busy: Boolean,
    saveError: String?,
    onDismiss: () -> Unit,
    onSave: (LocalRoutingGroup) -> Unit,
) {
    var name by remember(original.id) { mutableStateOf(original.name) }
    var domains by remember(original.id) { mutableStateOf(original.domains.joinToString("\n")) }
    var includeApp by remember(original.id) { mutableStateOf(original.includeOfficialApp) }
    var error by remember(original.id) { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (original.name.isBlank()) "创建服务分组" else "编辑 ${original.name}") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                OutlinedTextField(name, { name = it }, label = { Text("分组名称") }, singleLine = true,
                    enabled = !busy, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(domains, { domains = it }, label = { Text("域名，每行一个") }, minLines = 5, maxLines = 10,
                    enabled = !busy, modifier = Modifier.fillMaxWidth().padding(top = 12.dp))
                Text("例如 anthropic.com，会同时匹配其子域名。保存后可单独选择该组的固定节点。",
                    color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
                LocalRouting.officialAppName(original.id)?.let { appName ->
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 8.dp)) {
                        Text("包含官方 $appName App 的流量", color = Ink, fontSize = 12.sp, modifier = Modifier.weight(1f))
                        Switch(checked = includeApp, onCheckedChange = { includeApp = it }, enabled = !busy)
                    }
                }
                (error ?: saveError)?.let { ErrorText(it) }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("取消") } },
        confirmButton = {
            TextButton(onClick = {
                runCatching {
                    val updated = original.copy(name = name.trim(), domains = LocalRouting.normalizeDomains(domains), includeOfficialApp = includeApp)
                    LocalRouting.validate(policy.copy(groups = policy.groups.filterNot { it.id == updated.id } + updated))
                    updated
                }.onSuccess(onSave).onFailure { error = it.message }
            }, enabled = !busy) { Text(if (busy) "保存中…" else "保存") }
        },
    )
}

@Composable
private fun ToolsScreen(
    config: ManagedConfig?,
    connectionCount: Int,
    domainRoutes: List<DomainRouteStat>,
    logs: List<RuntimeLog>,
    diagnosticLogs: List<RuntimeLog>,
    phase: VpnPhase,
    coreVersion: String?,
) {
    var section by remember { mutableIntStateOf(0) }
    Column(Modifier.fillMaxSize()) {
        SegmentTabs(listOf("路由测试", "路由记录", "运行配置", "日志"), section) { section = it }
        when (section) {
            0 -> RouteTestScreen(connectionCount, phase)
            1 -> DomainRouteStatsScreen(domainRoutes)
            2 -> ConfigurationScreen(config)
            else -> LogsScreen(logs, diagnosticLogs, coreVersion)
        }
    }
}

@Composable
private fun DomainRouteStatsScreen(stats: List<DomainRouteStat>) {
    var query by remember { mutableStateOf("") }
    val routeCounts = remember(stats) {
        stats.groupBy { it.domain }.mapValues { (_, values) ->
            values.map { "${it.outbound}\u0000${it.chain.joinToString("\u0000")}" }.toSet().size
        }
    }
    val visible = remember(stats, query) {
        val wanted = query.trim()
        stats.filter { stat ->
            wanted.isEmpty() || listOf(stat.domain, stat.outbound, stat.rule)
                .plus(stat.chain)
                .any { it.contains(wanted, ignoreCase = true) }
        }
    }
    val totalConnections = stats.sumOf(DomainRouteStat::connectionCount)
    val mixedDomains = routeCounts.count { it.value > 1 }

    LazyColumn(
        contentPadding = PaddingValues(18.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            AppCard {
                Text("本地域名路由记录", color = Ink, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                Text(
                    "保存在 App 私有目录，只读展示 sing-box 实际连接；HTTPS 内部的单次 HTTP 请求无法读取。",
                    color = Muted,
                    fontSize = 12.sp,
                    lineHeight = 18.sp,
                    modifier = Modifier.padding(top = 5.dp),
                )
                HorizontalDivider(Modifier.padding(vertical = 13.dp), color = Line)
                InfoRow("域名 / 目标", routeCounts.size.toString())
                InfoRow("累计连接", totalConnections.toString())
                InfoRow("多路径域名", mixedDomains.toString())
            }
        }
        item {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("搜索域名、节点或规则") },
                shape = RoundedCornerShape(14.dp),
            )
        }
        if (stats.isEmpty()) {
            item { EmptyPanel("还没有路由记录，连接 VPN 并访问一些网站后会自动出现") }
        } else if (visible.isEmpty()) {
            item { EmptyPanel("没有符合搜索条件的路由记录") }
        } else {
            items(
                items = visible,
                key = { stat ->
                    "${stat.domain}\u0000${stat.outbound}\u0000${stat.chain.joinToString("\u0000")}\u0000${stat.rule}"
                },
            ) { stat ->
                AppCard {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            stat.domain,
                            color = Ink,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f),
                        )
                        if ((routeCounts[stat.domain] ?: 0) > 1) {
                            Text(
                                "多路径",
                                color = Warn,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(end = 7.dp),
                            )
                        }
                        DomainRouteBadge(stat)
                    }
                    Text(
                        stat.chain.filter(String::isNotBlank).joinToString(" → ")
                            .ifBlank { stat.outbound.ifBlank { "未知路径" } },
                        color = AccentDark,
                        fontSize = 12.sp,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(top = 7.dp),
                    )
                    HorizontalDivider(Modifier.padding(vertical = 11.dp), color = Line)
                    InfoRow("连接次数", stat.connectionCount.toString())
                    InfoRow("下行 / 上行", "${formatBytes(stat.downlinkTotal)} / ${formatBytes(stat.uplinkTotal)}")
                    InfoRow("命中规则", stat.rule.ifBlank { "默认规则" })
                    InfoRow("最后出现", formatTime(stat.lastSeen))
                }
            }
        }
    }
}

@Composable
private fun DomainRouteBadge(stat: DomainRouteStat) {
    val route = listOf(stat.outbound, stat.outboundType).plus(stat.chain)
        .joinToString(" ").lowercase()
    val (label, foreground, background) = when {
        "direct" in route -> Triple("直连", Color(0xFF78B7FF), Color(0xFF172D43))
        "block" in route || "reject" in route -> Triple("阻止", Danger, Color(0xFF3A2024))
        route.isNotBlank() -> Triple("代理", AccentDark, AccentSoft)
        else -> Triple("未知", Warn, Color(0xFF382F1E))
    }
    Text(
        label,
        color = foreground,
        fontSize = 10.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.clip(RoundedCornerShape(999.dp)).background(background)
            .padding(horizontal = 9.dp, vertical = 5.dp),
    )
}

@Composable
private fun RouteTestScreen(connectionCount: Int, phase: VpnPhase) {
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("https://example.com/") }
    var testing by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<RouteTestResult?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp)) {
        AppCard {
            Text("URL 实际路由测试", color = Ink, fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Text("请求会真实进入当前 VPN，并由 libbox 连接事件确认最终规则和出站。", color = Muted, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 5.dp))
            OutlinedTextField(value = url, onValueChange = { url = it }, label = { Text("HTTP/HTTPS URL") }, singleLine = true, modifier = Modifier.fillMaxWidth().padding(top = 14.dp))
            Button(
                onClick = {
                    scope.launch {
                        testing = true; error = null; result = null
                        runCatching { CoreGraph.repository.testRoute(url) }
                            .onSuccess { result = it }
                            .onFailure { error = it.message }
                        testing = false
                    }
                },
                enabled = phase == VpnPhase.CONNECTED && !testing,
                modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                shape = RoundedCornerShape(13.dp),
            ) { Text(if (testing) "正在发起请求并匹配连接…" else "开始测试") }
            if (phase != VpnPhase.CONNECTED) Text("请先连接 VPN", color = Warn, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
            error?.let { ErrorText(it) }
        }
        result?.let { RouteResultCard(it) }
        AppCard(Modifier.padding(top = 14.dp)) {
            InfoRow("当前捕获的连接", "$connectionCount 条")
            Text("测试不会保存 URL 查询参数；域名路由会在本机聚合保存，并同步到管理端用于核对分流。", color = Muted, fontSize = 11.sp, lineHeight = 17.sp, modifier = Modifier.padding(top = 10.dp))
        }
    }
}

@Composable
private fun RouteResultCard(result: RouteTestResult) {
    val color = when (result.decision) {
        RouteDecision.PROXY -> AccentDark
        RouteDecision.DIRECT -> Color(0xFF78B7FF)
        RouteDecision.BLOCK -> Danger
        RouteDecision.UNKNOWN -> Warn
    }
    AppCard(Modifier.padding(top = 14.dp)) {
        Text(
            when (result.decision) {
                RouteDecision.PROXY -> "经代理访问"
                RouteDecision.DIRECT -> "直接连接"
                RouteDecision.BLOCK -> "已阻止"
                RouteDecision.UNKNOWN -> "未确认路由"
            },
            color = color,
            fontWeight = FontWeight.Bold,
            fontSize = 20.sp,
        )
        Text(result.url, color = Muted, fontSize = 12.sp, maxLines = 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.padding(top = 4.dp))
        HorizontalDivider(Modifier.padding(vertical = 13.dp), color = Line)
        InfoRow("最终出站", result.outbound.ifBlank { "未捕获" })
        InfoRow("命中规则", result.rule.ifBlank { "未报告" })
        InfoRow("代理链", result.chain.ifEmpty { listOf("—") }.joinToString(" → "))
        InfoRow("耗时 / HTTP", "${result.latencyMillis} ms · ${result.httpStatus ?: "—"}")
        result.error?.let { ErrorText(it) }
    }
}

@Composable
private fun ConfigurationScreen(config: ManagedConfig?) {
    if (config == null) {
        EmptyPanel("尚未同步运行配置")
        return
    }
    val summary = remember(config.content) { runCatching { ConfigInspector.inspect(config.content) }.getOrNull() }
    var tab by remember { mutableIntStateOf(0) }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            SourceBadge(config.ruleSource)
            Text(config.profileName, color = Muted, fontSize = 12.sp, modifier = Modifier.padding(start = 8.dp))
            Spacer(Modifier.weight(1f))
            Text(shortEtag(config.etag), color = Muted, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }
        SegmentTabs(listOf("概览", "路由", "JSON"), tab) { tab = it }
        if (summary == null) {
            EmptyPanel("配置解析失败")
        } else when (tab) {
            0 -> LazyColumn(contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                item { AppCard { InfoRow("入口", summary.inboundTypes.joinToString().ifBlank { "无" }); InfoRow("DNS 服务器", summary.dnsServers.toString()); InfoRow("路由规则", summary.routeRules.size.toString()); InfoRow("默认出站", summary.routeFinal); InfoRow("出站节点", summary.outboundTags.size.toString()) } }
                item {
                    AppCard {
                        Text("服务器配置 + 本机服务分组", color = Ink, fontWeight = FontWeight.Bold)
                        Text("下面展示合并后的实际运行规则。Claude、GPT、自定义分组和默认代理使用手机保存的设置，配置版本标识服务器同步版本。",
                            color = Muted, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 6.dp))
                    }
                }
            }
            1 -> LazyColumn(contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(summary.routeRules) { rule -> AppCard { Text(rule, color = Ink, fontSize = 13.sp, lineHeight = 19.sp) } }
            }
            else -> SelectionContainer {
                Text(
                    summary.sanitizedJson,
                    color = Color(0xFFD8E4EE),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    lineHeight = 17.sp,
                    modifier = Modifier.fillMaxSize().background(CodeBackground).verticalScroll(rememberScrollState()).horizontalScroll(rememberScrollState()).padding(16.dp),
                )
            }
        }
    }
}

@Composable
private fun LogsScreen(logs: List<RuntimeLog>, diagnosticLogs: List<RuntimeLog>, coreVersion: String?) {
    val scope = rememberCoroutineScope()
    var uploading by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("本地诊断 · ${diagnosticLogs.size}", color = Ink, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                Text("libbox ${logs.size} 行 · App 私有目录持久保存", color = Muted, fontSize = 10.sp)
            }
            TextButton(
                onClick = {
                    scope.launch {
                        uploading = true
                        message = null
                        runCatching {
                            CoreGraph.repository.uploadDiagnostics(BuildConfig.VERSION_NAME, coreVersion.orEmpty())
                        }.onSuccess { reportId ->
                            message = "上传成功 · 报告 ${reportId.take(8)}"
                        }.onFailure { error ->
                            message = "上传失败：${error.message ?: error.javaClass.simpleName}"
                        }
                        uploading = false
                    }
                },
                enabled = !uploading,
            ) { Text(if (uploading) "上传中…" else "上传诊断") }
            TextButton(onClick = { scope.launch { CoreGraph.repository.clearRuntimeLogs() } }) { Text("清空") }
        }
        Text(
            "上传内容包含网络切换、VPN 生命周期、脱敏后的 libbox 日志和设备环境；不会上传注册令牌或节点密码，日志可能包含故障相关的目标地址。",
            color = Muted,
            fontSize = 10.sp,
            lineHeight = 15.sp,
            modifier = Modifier.padding(horizontal = 18.dp, vertical = 4.dp),
        )
        message?.let {
            Text(it, color = if (it.startsWith("上传成功")) AccentDark else Warn, fontSize = 11.sp, modifier = Modifier.padding(horizontal = 18.dp, vertical = 4.dp))
        }
        if (diagnosticLogs.isEmpty()) EmptyPanel("本地诊断尚无记录")
        else LazyColumn(Modifier.fillMaxSize().background(CodeBackground), contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            items(diagnosticLogs.asReversed().take(800)) { line ->
                Text(line.message, color = logColor(line.level), fontFamily = FontFamily.Monospace, fontSize = 10.sp, lineHeight = 15.sp)
            }
        }
    }
}

@Composable
private fun SettingsScreen(control: ControlPlaneSnapshot, coreVersion: String?, phase: VpnPhase, onDisconnect: () -> Unit) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val context = androidx.compose.ui.platform.LocalContext.current
    var batteryExempt by remember { mutableStateOf(false) }
    androidx.lifecycle.compose.LifecycleEventEffect(androidx.lifecycle.Lifecycle.Event.ON_RESUME) {
        batteryExempt = context.getSystemService(android.os.PowerManager::class.java)
            .isIgnoringBatteryOptimizations(context.packageName)
    }
    var message by remember { mutableStateOf<String?>(null) }
    LazyColumn(contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            AppCard {
                Text("设备与中心", color = Ink, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Spacer(Modifier.height(10.dp))
                InfoRow("设备", control.enrollment?.hostName.orEmpty())
                InfoRow("服务器", control.enrollment?.server.orEmpty())
                InfoRow("Profile", control.config?.profileName ?: control.enrollment?.profileName.orEmpty())
                InfoRow("App / Core", "${BuildConfig.VERSION_NAME} / ${coreVersion.orEmpty()}")
                if (control.enrollment?.server?.startsWith("http://") == true) {
                    Text("当前中心使用明文 HTTP，仅适合受控测试。正式使用请配置 HTTPS。", color = Warn, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 10.dp))
                }
            }
        }
        item {
            AppCard {
                Text("配置与恢复", color = Ink, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text("新配置会先校验，再热更新；失败时保留上一份可用配置。控制面请求始终绕过 VPN 走底层网络。", color = Muted, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 7.dp))
                OutlinedButton(onClick = { scope.launch { runCatching { CoreGraph.repository.syncConfiguration(force = true) }.onFailure { message = it.message } } }, modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) { Text("立即同步配置") }
                OutlinedButton(onClick = { clipboard.setText(AnnotatedString(control.enrollment?.server.orEmpty())); message = "服务器地址已复制" }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("复制服务器地址") }
                message?.let { Text(it, color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp)) }
            }
        }
        item {
            AppCard {
                Text("后台恢复", color = Ink, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text(if (batteryExempt) "系统电池优化：已豁免" else "系统电池优化：尚未豁免，休眠时可能暂停网络", color = if (batteryExempt) AccentDark else Warn, fontSize = 12.sp)
                Text("VPN 服务会在后台定期检测连接并自动恢复。小米/HyperOS 请将本应用的省电策略设为“不限制”，并允许后台运行；系统强制暂停应用时，检测也会暂停。", color = Muted, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 7.dp))
                OutlinedButton(onClick = {
                    runCatching { context.startActivity(Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
                        .onFailure { message = "无法打开电池设置，请从系统设置中操作" }
                }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("电池优化设置") }
                OutlinedButton(onClick = {
                    runCatching { context.startActivity(Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}"))) }
                        .onFailure { message = "无法打开应用设置" }
                }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) { Text("应用后台与省电设置") }
                Spacer(Modifier.height(12.dp))
                Text("系统 VPN", color = Ink, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text("支持 Android Always-on VPN；可在系统的 VPN 设置中启用。网络切换时会自动选择已验证的 Wi‑Fi、以太网或蜂窝网络。", color = Muted, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 7.dp))
                if (phase == VpnPhase.CONNECTED) OutlinedButton(onClick = onDisconnect, modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) { Text("断开 VPN", color = Danger) }
            }
        }
        item {
            AppCard {
                Text("重新注册", color = Danger, fontWeight = FontWeight.Bold)
                Text("会清除本机凭据、配置和服务分组设置。中心端设备不会被删除。", color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 5.dp))
                OutlinedButton(
                    onClick = { scope.launch { runCatching { CoreGraph.repository.forgetDevice() }.onFailure { message = it.message } } },
                    enabled = (phase == VpnPhase.DISCONNECTED || phase == VpnPhase.ERROR) && control.syncPhase != SyncPhase.SYNCING,
                    modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
                ) { Text("清除本机并重新注册", color = Danger) }
            }
        }
    }
}

@Composable
private fun SegmentTabs(labels: List<String>, selected: Int, onSelect: (Int) -> Unit) {
    Row(Modifier.fillMaxWidth().background(SurfaceColor).padding(horizontal = 18.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
        labels.forEachIndexed { index, label ->
            TextButton(
                onClick = { onSelect(index) },
                modifier = Modifier.weight(1f).clip(RoundedCornerShape(10.dp)).background(if (selected == index) AccentSoft else Color.Transparent),
            ) { Text(label, color = if (selected == index) AccentDark else Muted, fontWeight = if (selected == index) FontWeight.Bold else FontWeight.Normal) }
        }
    }
}

@Composable
private fun AppCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = SurfaceColor),
        shape = RoundedCornerShape(18.dp),
        border = BorderStroke(1.dp, Line),
        modifier = modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(17.dp), content = content)
    }
}

@Composable
private fun StatCard(label: String, value: String, modifier: Modifier = Modifier) {
    Card(colors = CardDefaults.cardColors(containerColor = SurfaceColor), shape = RoundedCornerShape(16.dp), border = BorderStroke(1.dp, Line), modifier = modifier) {
        Column(Modifier.padding(15.dp)) {
            Text(label, color = Muted, fontSize = 11.sp)
            Text(value, color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 3.dp))
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.Top) {
        Text(label, color = Muted, fontSize = 12.sp, modifier = Modifier.width(92.dp))
        Text(value, color = Ink, fontSize = 12.sp, modifier = Modifier.weight(1f), textAlign = androidx.compose.ui.text.style.TextAlign.End)
    }
}

@Composable
private fun SourceBadge(source: String?) {
    val quickJs = source == "quickjs"
    Text(
        if (quickJs) "QuickJS 生成" else "Profile",
        color = if (quickJs) Color(0xFFC7A6FF) else AccentDark,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.clip(RoundedCornerShape(999.dp)).background(if (quickJs) Color(0xFF302440) else AccentSoft).padding(horizontal = 9.dp, vertical = 5.dp),
    )
}

@Composable
private fun StatusChip(active: Boolean, label: String) {
    Row(Modifier.clip(RoundedCornerShape(999.dp)).background(if (active) AccentSoft else Background).padding(horizontal = 10.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(7.dp).clip(CircleShape).background(if (active) Accent else Muted))
        Text(label, color = if (active) AccentDark else Muted, fontSize = 11.sp, modifier = Modifier.padding(start = 6.dp))
    }
}

@Composable
private fun DelayBadge(delay: Int) {
    val color = when {
        delay <= 0 -> Muted
        delay < 200 -> AccentDark
        delay < 500 -> Warn
        else -> Danger
    }
    Text(if (delay > 0) "$delay ms" else "未测试", color = color, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
}

@Composable
private fun ErrorText(message: String) {
    Text(message, color = Danger, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.fillMaxWidth().padding(top = 10.dp).clip(RoundedCornerShape(10.dp)).background(Color(0xFF351C22)).padding(10.dp))
}

@Composable
private fun EmptyPanel(message: String) {
    Box(Modifier.fillMaxSize().padding(28.dp), contentAlignment = Alignment.Center) { Text(message, color = Muted, fontSize = 14.sp) }
}

private fun shortEtag(etag: String?): String = etag?.trim('"')?.take(12)?.ifBlank { "—" } ?: "—"
private fun formatTime(value: Long?): String = value?.takeIf { it > 0 }?.let { java.text.DateFormat.getDateTimeInstance().format(java.util.Date(it)) } ?: "尚未同步"
private fun formatRate(value: Long): String = "${formatBytes(value)}/s"
private fun formatBytes(value: Long): String = when {
    value < 1_024 -> "$value B"
    value < 1_048_576 -> "%.1f KB".format(value / 1_024.0)
    value < 1_073_741_824 -> "%.1f MB".format(value / 1_048_576.0)
    else -> "%.2f GB".format(value / 1_073_741_824.0)
}
private fun logColor(level: Int): Color = when {
    level >= 5 -> Color(0xFFFF8E8E)
    level == 4 -> Color(0xFFFFCD82)
    else -> Color(0xFFD8E4EE)
}
