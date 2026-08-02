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
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
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
import io.sbeasy.android.core.ControlPlaneSnapshot
import io.sbeasy.android.core.CoreGraph
import io.sbeasy.android.core.EnrollmentUriParser
import io.sbeasy.android.core.ManagedConfig
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)

        val intent = VpnService.prepare(this)
        if (intent == null) startVpnService() else vpnPermission.launch(intent)
    }

    private fun startVpnService() {
        ContextCompat.startForegroundService(
            this,
            Intent(this, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_START),
        )
    }

    private fun stopVpnService() {
        startService(Intent(this, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_STOP))
    }
}

private val Background = Color(0xFFF4F6F8)
private val SurfaceColor = Color(0xFFFFFFFF)
private val Ink = Color(0xFF18212B)
private val Muted = Color(0xFF718096)
private val Line = Color(0xFFE6EAF0)
private val Accent = Color(0xFF2DBE8C)
private val AccentDark = Color(0xFF168565)
private val AccentSoft = Color(0xFFE5F8F1)
private val Danger = Color(0xFFD95252)
private val Warn = Color(0xFFF0A23B)
private val CodeBackground = Color(0xFF17212B)

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
    val logs by RuntimeObservability.logs.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var selectedTab by remember { mutableIntStateOf(0) }
    var actionError by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(control.enrollment?.hostId) {
        if (control.enrollment != null && vpn.phase != VpnPhase.CONNECTED) {
            runCatching { CoreGraph.repository.syncConfiguration() }
        }
    }

    MaterialTheme(
        colorScheme = lightColorScheme(
            primary = AccentDark,
            secondary = Accent,
            background = Background,
            surface = SurfaceColor,
            error = Danger,
            onPrimary = Color.White,
            onBackground = Ink,
            onSurface = Ink,
        ),
    ) {
        Surface(color = Background, modifier = Modifier.fillMaxSize()) {
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

            Scaffold(
                containerColor = Background,
                topBar = { AppHeader(control, vpn.phase) },
                bottomBar = {
                    NavigationBar(containerColor = SurfaceColor, tonalElevation = 0.dp) {
                        listOf("⌂" to "首页", "◈" to "代理", "⌘" to "工具", "⚙" to "设置")
                            .forEachIndexed { index, item ->
                                NavigationBarItem(
                                    selected = selectedTab == index,
                                    onClick = { selectedTab = index },
                                    icon = { Text(item.first, fontSize = 19.sp) },
                                    label = { Text(item.second, fontSize = 11.sp) },
                                    colors = NavigationBarItemDefaults.colors(
                                        selectedIconColor = AccentDark,
                                        selectedTextColor = AccentDark,
                                        indicatorColor = AccentSoft,
                                        unselectedIconColor = Muted,
                                        unselectedTextColor = Muted,
                                    ),
                                )
                            }
                    }
                },
            ) { padding ->
                Box(Modifier.padding(padding).fillMaxSize()) {
                    when (selectedTab) {
                        0 -> HomeScreen(control, vpn.phase, vpn.detail, vpn.error, traffic, groups, onConnect, onDisconnect)
                        1 -> ProxiesScreen(groups, vpn.phase)
                        2 -> ToolsScreen(control.config, connections.size, logs, vpn.phase)
                        else -> SettingsScreen(control, vpn.coreVersion, vpn.phase, onDisconnect)
                    }
                }
            }
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
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
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

@Composable
private fun HomeScreen(
    control: ControlPlaneSnapshot,
    phase: VpnPhase,
    detail: String,
    runtimeError: String?,
    traffic: TrafficSnapshot,
    groups: List<ProxyGroupSnapshot>,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val connected = phase == VpnPhase.CONNECTED
    val busy = phase == VpnPhase.STARTING || phase == VpnPhase.STOPPING
    val selectedProxy = groups.firstOrNull { it.selected.isNotBlank() }?.selected ?: "等待代理组数据"
    LazyColumn(contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = if (connected) Color(0xFF183F36) else Color(0xFF263341)),
                shape = RoundedCornerShape(26.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(22.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(if (connected) "安全连接已建立" else detail, color = Color.White, fontSize = 19.sp, fontWeight = FontWeight.Bold)
                    Text(selectedProxy, color = if (connected) Color(0xFFA9F0D6) else Color(0xFFB7C2CE), fontSize = 13.sp, modifier = Modifier.padding(top = 6.dp))
                    Button(
                        onClick = if (connected) onDisconnect else onConnect,
                        enabled = !busy && control.config != null,
                        modifier = Modifier.size(132.dp).padding(top = 18.dp),
                        shape = CircleShape,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (connected) Accent else Color(0xFF415064),
                            contentColor = Color.White,
                        ),
                    ) { Text(if (connected) "断开" else "连接", fontSize = 20.sp, fontWeight = FontWeight.Bold) }
                    if (control.config == null) Text("先同步配置后才能连接", color = Color(0xFFFFD9A1), fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp))
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
private fun ProxiesScreen(groups: List<ProxyGroupSnapshot>, phase: VpnPhase) {
    val scope = rememberCoroutineScope()
    var busyGroup by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    if (groups.isEmpty()) {
        EmptyPanel(if (phase == VpnPhase.CONNECTED) "正在读取真实代理组…" else "连接 VPN 后可查看、切换和测速节点")
        return
    }
    LazyColumn(contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        items(groups, key = { it.tag }) { group ->
            AppCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(group.tag, color = Ink, fontSize = 17.sp, fontWeight = FontWeight.Bold)
                        Text("${group.type} · 当前 ${group.selected.ifBlank { "自动选择" }}", color = Muted, fontSize = 12.sp)
                    }
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                busyGroup = group.tag
                                error = null
                                runCatching { CoreGraph.repository.testGroup(group.tag) }
                                    .onFailure { error = it.message }
                                busyGroup = null
                            }
                        },
                        enabled = busyGroup == null,
                    ) { Text(if (busyGroup == group.tag) "测速中" else "全部测速") }
                }
                Spacer(Modifier.height(10.dp))
                group.items.forEach { proxy ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(vertical = 5.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = group.selected == proxy.tag,
                            onClick = if (group.selectable) ({
                                scope.launch {
                                    error = null
                                    runCatching { CoreGraph.repository.selectOutbound(group.tag, proxy.tag) }
                                        .onFailure { error = it.message }
                                }
                            }) else null,
                        )
                        Column(Modifier.weight(1f)) {
                            Text(proxy.tag, color = Ink, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(proxy.type, color = Muted, fontSize = 11.sp)
                        }
                        DelayBadge(proxy.urlTestDelay)
                    }
                }
                error?.let { ErrorText(it) }
            }
        }
    }
}

@Composable
private fun ToolsScreen(config: ManagedConfig?, connectionCount: Int, logs: List<RuntimeLog>, phase: VpnPhase) {
    var section by remember { mutableIntStateOf(0) }
    Column(Modifier.fillMaxSize()) {
        SegmentTabs(listOf("路由测试", "运行配置", "日志"), section) { section = it }
        when (section) {
            0 -> RouteTestScreen(connectionCount, phase)
            1 -> ConfigurationScreen(config)
            else -> LogsScreen(logs)
        }
    }
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
            Text("测试不会保存 URL 查询参数；遥测只上传聚合流量，不上传访问域名。", color = Muted, fontSize = 11.sp, lineHeight = 17.sp, modifier = Modifier.padding(top = 10.dp))
        }
    }
}

@Composable
private fun RouteResultCard(result: RouteTestResult) {
    val color = when (result.decision) {
        RouteDecision.PROXY -> AccentDark
        RouteDecision.DIRECT -> Color(0xFF3478C2)
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
                item { AppCard { Text(if (config.ruleSource == "quickjs") "中心 QuickJS 已执行" else "Profile 模板规则", color = Ink, fontWeight = FontWeight.Bold); Text(if (config.ruleSource == "quickjs") "下面展示的是脚本生成并由手机核心校验后的最终规则；脚本本身仍只在中心端运行。" else "当前规则直接来自中心 Profile。", color = Muted, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 6.dp)) } }
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
private fun LogsScreen(logs: List<RuntimeLog>) {
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("libbox 实时日志 · ${logs.size}", color = Muted, fontSize = 12.sp)
            Spacer(Modifier.weight(1f))
            TextButton(onClick = { scope.launch { CoreGraph.repository.clearRuntimeLogs() } }) { Text("清空") }
        }
        if (logs.isEmpty()) EmptyPanel("连接后将在这里显示 libbox 实时日志")
        else LazyColumn(Modifier.fillMaxSize().background(CodeBackground), contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            items(logs.asReversed().take(500)) { line ->
                Text(line.message, color = logColor(line.level), fontFamily = FontFamily.Monospace, fontSize = 10.sp, lineHeight = 15.sp)
            }
        }
    }
}

@Composable
private fun SettingsScreen(control: ControlPlaneSnapshot, coreVersion: String?, phase: VpnPhase, onDisconnect: () -> Unit) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
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
                Text("系统 VPN", color = Ink, fontWeight = FontWeight.Bold, fontSize = 17.sp)
                Text("支持 Android Always-on VPN；可在系统的 VPN 设置中启用。网络切换时会自动选择已验证的 Wi‑Fi、以太网或蜂窝网络。", color = Muted, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.padding(top = 7.dp))
                if (phase == VpnPhase.CONNECTED) OutlinedButton(onClick = onDisconnect, modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) { Text("断开 VPN", color = Danger) }
            }
        }
        item {
            AppCard {
                Text("重新注册", color = Danger, fontWeight = FontWeight.Bold)
                Text("会清除本机加密凭据和配置快照。中心端设备不会被删除。", color = Muted, fontSize = 12.sp, modifier = Modifier.padding(top = 5.dp))
                OutlinedButton(
                    onClick = { runCatching { CoreGraph.repository.forgetDevice() }.onFailure { message = it.message } },
                    enabled = phase != VpnPhase.CONNECTED,
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
    Card(colors = CardDefaults.cardColors(containerColor = SurfaceColor), shape = RoundedCornerShape(18.dp), modifier = modifier.fillMaxWidth()) {
        Column(Modifier.padding(17.dp), content = content)
    }
}

@Composable
private fun StatCard(label: String, value: String, modifier: Modifier = Modifier) {
    Card(colors = CardDefaults.cardColors(containerColor = SurfaceColor), shape = RoundedCornerShape(16.dp), modifier = modifier) {
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
        color = if (quickJs) Color(0xFF7A4BC4) else AccentDark,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.clip(RoundedCornerShape(999.dp)).background(if (quickJs) Color(0xFFF0E9FC) else AccentSoft).padding(horizontal = 9.dp, vertical = 5.dp),
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
    Text(message, color = Danger, fontSize = 12.sp, lineHeight = 18.sp, modifier = Modifier.fillMaxWidth().padding(top = 10.dp).clip(RoundedCornerShape(10.dp)).background(Color(0xFFFFEEEE)).padding(10.dp))
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
