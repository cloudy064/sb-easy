package io.sbeasy.android

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import io.sbeasy.android.core.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun AppUpdatesScreen(onBack: () -> Unit, onDisconnect: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snapshot by AppUpdateStore.state.collectAsState()
    val runtime by VpnRuntimeState.state.collectAsState()
    val preferences = remember { context.getSharedPreferences("app_catalog_ui", android.content.Context.MODE_PRIVATE) }
    var url by remember { mutableStateOf(preferences.getString("url", "").orEmpty()) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var installStatus by remember { mutableStateOf(AppUpdateInstaller.status(context)) }
    var pending by remember { mutableStateOf<CachedApp?>(null) }
    var exporting by remember { mutableStateOf<CachedApp?>(null) }
    var confirmed by remember { mutableStateOf<CachedApp?>(null) }
    var rescuePassword by remember { mutableStateOf("") }
    var rescueRepeat by remember { mutableStateOf("") }
    var rescueReadyFor by remember { mutableStateOf<String?>(null) }
    var rescuePending by remember { mutableStateOf<Pair<CachedApp, CharArray>?>(null) }
    DisposableEffect(Unit) { onDispose { rescuePending?.second?.fill('\u0000') } }
    var showPreferences by remember { mutableStateOf(false) }
    val occupied = busy || snapshot.busy
    val installedBuild = AppPackagePolicy.currentBuild(context)
    if (showPreferences) { PreferencesScreen(onBack = { showPreferences = false }); return }
    BackHandler(enabled = !occupied, onBack = onBack)
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { installStatus = AppUpdateInstaller.status(context) }
    fun action(block: suspend () -> Unit) {
        busy = true; message = ""
        scope.launch {
            try { block() }
            catch (failure: Exception) { message = failure.message ?: "应用更新操作失败" }
            finally { busy = false; installStatus = AppUpdateInstaller.status(context) }
        }
    }
    suspend fun install(candidate: CachedApp) {
        require(AppUpdateInstaller.stopped()) { "请先断开 VPN，再安装更新" }
        pending = candidate
        if (Build.VERSION.SDK_INT >= 26 && !context.packageManager.canRequestPackageInstalls()) {
            context.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}")))
            message = "允许此来源安装后返回，点击继续系统安装。"
        } else {
            AppUpdateInstaller.install(context, candidate)
            pending = null; message = "已提交系统安装会话，请确认安装。"
        }
    }
    val catalogFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) action {
            val text = withContext(Dispatchers.IO) { requireNotNull(context.contentResolver.openInputStream(uri)).use {
                PreferencesEnvelope.utf8(AppRuntimeProvenance.readBounded(it, PluginCatalog.MAX_ENVELOPE))
            } }
            AppUpdateStore.accept(text); message = "已核验应用目录签名、序号与累计撤销记录。"
        }
    }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
        val candidate = exporting; exporting = null
        if (uri != null && candidate != null) action {
            requireNotNull(context.contentResolver.openOutputStream(uri, "wt")).use { AppUpdateStore.exportRecovery(candidate, it) }
            message = "已导出 APK、签名目录及恢复说明。请另行导出加密偏好，并在卸载前确认两份文件已保存在应用外。"
        }
    }
    val rescueFile = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
        val prepared = rescuePending; rescuePending = null
        if (uri == null || prepared == null) prepared?.second?.fill('\u0000')
        else action {
            try {
                val proof = AppUpdateRescue.export(context, prepared.first, uri, prepared.second)
                rescueReadyFor = prepared.first.release.sha256
                message = if (proof.recoveryBuild >= proof.targetBuild && proof.targetBuild > proof.installedBuild)
                    "已保存并读回验证救援包。原版已撤销或无合格旧版，包内仅能重新安装目标版本，不能回退旧版；加密偏好已保存。"
                    else "已保存并读回验证应用外救援包，含恢复 APK、签名回执、加密偏好和操作说明。即使新版无法启动，也可从文件管理器恢复。"
            } finally { prepared.second.fill('\u0000') }
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        TextButton(enabled = !occupied, onClick = onBack) { Text("返回设置") }
        Text("应用与内核更新", style = MaterialTheme.typography.headlineSmall)
        Text("当前 ${BuildConfig.VERSION_NAME}（构建 $installedBuild）· 内核 ${runtime.coreVersion.orEmpty()}")
        Text("应用与内核一起更新。每个安装包都会核验发布者目录、当前应用签名、实际版本与架构，以及 APK 中的内核来源和原生库。安装由 Android 系统确认。")
        snapshot.revoked[installedBuild]?.let { Text("当前版本已撤销：$it。请更新；此版本不会保留为恢复选项。", color = MaterialTheme.colorScheme.error) }
        if (snapshot.trustedKeyCount == 0) Text("此构建尚未配置应用更新发布者公钥，在线更新与目录导入已关闭。", color = MaterialTheme.colorScheme.error)
        OutlinedTextField(url, { url = it }, enabled = !occupied, label = { Text("HTTPS 应用签名目录地址") }, modifier = Modifier.fillMaxWidth())
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = !occupied && snapshot.trustedKeyCount > 0, onClick = { action {
                AppUpdateStore.refresh(url); preferences.edit().putString("url", url).apply(); message = "已读取签名目录。"
            } }) { Text("读取目录") }
            OutlinedButton(enabled = !occupied && snapshot.trustedKeyCount > 0, onClick = { catalogFile.launch(arrayOf("application/json", "application/octet-stream", "*/*")) }) { Text("选择目录文件") }
        }
        snapshot.catalog?.let { catalog ->
            Text("目录序号 ${catalog.sequence} · " + if (catalog.fresh()) "有效" else "已过期，刷新后才能下载")
            Text("离线缓存只能反映此前已获取的撤销记录。更新前会保留当前已验证 APK；目录需包含当前安装包的恢复记录。", style = MaterialTheme.typography.bodySmall)
            val releases = catalog.releases.filter { release -> release.abis.any { it in Build.SUPPORTED_ABIS } }
                .sortedBy { it.abis.size }.distinctBy { it.build }.sortedByDescending { it.build }
            releases.forEach { release -> Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("${release.version}（${release.build}）· 内核 ${release.coreVersion}", style = MaterialTheme.typography.titleSmall)
                Text("${release.abis.joinToString()} · ${release.bytes / 1024 / 1024} MiB · Android API ${release.minOs}+", style = MaterialTheme.typography.bodySmall)
                snapshot.revoked[release.build]?.let { Text("已撤销：$it", color = MaterialTheme.colorScheme.error) }
                if (!AppUpdateStore.compatible(release)) Text("不符合本机签名、系统或架构要求。", style = MaterialTheme.typography.bodySmall)
                Button(enabled = !occupied && catalog.fresh() && release.build > installedBuild && AppUpdateStore.compatible(release), onClick = { action {
                    val downloaded = AppUpdateStore.download(release); rescueReadyFor = null; confirmed = downloaded
                } }) { Text("下载并验证更新") }
            } } }
        }
        if (runtime.phase !in setOf(VpnPhase.DISCONNECTED, VpnPhase.ERROR) || RuntimeBridge.control != null) {
            Text("安装前需要断开 VPN。下载与验证可以先完成。")
            OutlinedButton(enabled = !occupied, onClick = onDisconnect) { Text("断开 VPN") }
        }
        if (snapshot.cached.isNotEmpty()) Text("安装与恢复缓存", style = MaterialTheme.typography.titleMedium)
        snapshot.cached.forEach { cached -> Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("${cached.release.version}（${cached.release.build}）")
            if (cached.release.build >= installedBuild) OutlinedButton(enabled = !occupied && AppUpdateStore.compatible(cached.release), onClick = { rescueReadyFor = null; confirmed = cached }) { Text("验证并交给系统安装") }
            else Text("此版本需要先卸载当前应用才能恢复。卸载会清除应用私有数据；请先完成下面两项导出。", style = MaterialTheme.typography.bodySmall)
            OutlinedButton(enabled = !occupied && AppUpdateStore.compatible(cached.release), onClick = {
                exporting = cached; export.launch("sb-easy-recovery-${cached.release.version}-${cached.release.build}.zip")
            }) { Text("导出已验证 APK 恢复包") }
        } } }
        OutlinedButton(enabled = !occupied, onClick = { showPreferences = true }) { Text("导出加密偏好备份") }
        Text("降级恢复：先把恢复 ZIP 与加密偏好保存到应用外并确认可读取，再手动卸载、解压并安装旧 APK。偏好备份不含设备令牌、WireGuard 私钥、CA 或更新信任状态；受管设备需重新注册。重装后读取新目录恢复最新撤销记录。此过程不能保证无损回滚。", style = MaterialTheme.typography.bodySmall)
        pending?.let { candidate -> OutlinedButton(enabled = !occupied, onClick = { action { install(candidate) } }) { Text("继续系统安装") } }
        if (occupied) { LinearProgressIndicator(Modifier.fillMaxWidth()); if (snapshot.total > 0) Text("${snapshot.received / 1024} / ${snapshot.total / 1024} KiB") }
        if (message.isNotEmpty()) Text(message)
        if (installStatus.isNotEmpty()) Text(installStatus, style = MaterialTheme.typography.bodySmall)
        if (snapshot.error.isNotEmpty()) Text(snapshot.error, color = MaterialTheme.colorScheme.error)
    }
    confirmed?.let { candidate -> AlertDialog(onDismissRequest = { if (!occupied) { confirmed = null; rescuePassword = ""; rescueRepeat = "" } }, title = { Text("安装前保存应用外救援包") }, text = {
        Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("即将安装 ${candidate.release.version}（${candidate.release.build}），内核 ${candidate.release.coreVersion}。先断开 VPN，把恢复 APK、签名回执、加密偏好和说明保存到应用外；成功读回后才能提交系统安装。")
            if (installedBuild in snapshot.revoked) Text("当前版已撤销，不会作为恢复 APK。优先保存已验证的安全旧版；没有安全旧版时只保存目标 APK 与偏好，不能承诺回退旧版。", color = MaterialTheme.colorScheme.error)
            if (rescueReadyFor == candidate.release.sha256) Text(message)
            else {
                Text("请记住恢复口令。卸载重装会丢失设备令牌和 WireGuard 密钥，受管设备需重新注册；系统用户 CA 需另行移除。")
                OutlinedTextField(rescuePassword, { rescuePassword = it }, enabled = !occupied, label = { Text("恢复口令（至少 12 个 UTF-8 字节）") },
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password))
                OutlinedTextField(rescueRepeat, { rescueRepeat = it }, enabled = !occupied, label = { Text("再次输入恢复口令") },
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password))
                if (message.isNotEmpty()) Text(message, color = MaterialTheme.colorScheme.error)
            }
        }
    }, confirmButton = {
        if (rescueReadyFor == candidate.release.sha256) TextButton(enabled = !occupied && AppUpdateInstaller.stopped(), onClick = { confirmed = null; action { install(candidate) } }) { Text("交给系统确认") }
        else TextButton(enabled = !occupied && AppUpdateInstaller.stopped() && rescuePassword == rescueRepeat && rescuePassword.toByteArray(Charsets.UTF_8).size >= 12, onClick = {
            rescuePending?.second?.fill('\u0000'); rescuePending = candidate to rescuePassword.toCharArray()
            rescuePassword = ""; rescueRepeat = ""; message = ""
            rescueFile.launch("sb-easy-before-${candidate.release.version}-${candidate.release.build}-rescue.zip")
        }) { Text("保存并验证救援包") }
    }, dismissButton = { TextButton(enabled = !occupied, onClick = { confirmed = null; rescuePassword = ""; rescueRepeat = "" }) { Text("稍后安装") } }) }
}
