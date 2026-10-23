package io.sbeasy.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import io.sbeasy.android.core.*
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun PluginManagerScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snapshot by PluginTrustStore.state.collectAsState()
    val preferences = remember { context.getSharedPreferences("plugin_catalog_ui", android.content.Context.MODE_PRIVATE) }
    var url by remember { mutableStateOf(preferences.getString("url", "").orEmpty()) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var pending by remember { mutableStateOf<CachedPlugin?>(null) }
    var recovery by remember { mutableStateOf<CachedPlugin?>(null) }
    var confirm by remember { mutableStateOf<CachedPlugin?>(null) }
    var installed by remember { mutableStateOf(HttpDebugPackagePolicy.installed(context)) }
    val occupied = busy || snapshot.busy
    BackHandler(enabled = !occupied, onBack = onBack)
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { installed = HttpDebugPackagePolicy.installed(context) }
    fun action(block: suspend () -> Unit) {
        busy = true; message = ""
        scope.launch {
            try { block() }
            catch (failure: Exception) { message = failure.message ?: "插件操作失败，现有安装保留" }
            finally { busy = false; installed = HttpDebugPackagePolicy.installed(context) }
        }
    }
    fun install(file: File) {
        pending = requireNotNull(PluginTrustStore.state.value.cached.firstOrNull { it.file.canonicalPath == file.canonicalPath }) { "已验证的目录回执不可用" }
        if (Build.VERSION.SDK_INT >= 26 && !context.packageManager.canRequestPackageInstalls()) {
            context.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}")))
            message = "请允许此来源安装，返回后继续安装已验证的文件。"
        } else {
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.httpdebug.files", file)
            context.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
            message = "请完成系统安装；返回调试页后手动启动引擎。失败时可在这里恢复缓存版本。"
        }
    }
    val uninstall = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val candidate = recovery; recovery = null
        if (result.resultCode == Activity.RESULT_OK && candidate != null) action {
            check(HttpDebugPackagePolicy.installed(context) == null) { "插件尚未卸载，未执行降级安装" }
            install(PluginTrustStore.prepareCached(candidate))
        } else message = "恢复已取消，缓存文件保留。"
    }
    val catalogFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) action {
            val data = withContext(Dispatchers.IO) {
                requireNotNull(context.contentResolver.openInputStream(uri)).use { input ->
                    val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192)
                    while (true) {
                        val read = input.read(buffer); if (read < 0) break
                        require(output.size() + read <= PluginCatalog.MAX_ENVELOPE) { "目录超过 1 MiB" }
                        output.write(buffer, 0, read)
                    }
                    PreferencesEnvelope.utf8(output.toByteArray())
                }
            }
            PluginTrustStore.accept(data); message = "已验证目录签名、版本与撤销记录。"
        }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        TextButton(enabled = !occupied, onClick = onBack) { Text("返回 HTTP(S) 调试") }
        Text("插件更新与恢复", style = MaterialTheme.typography.headlineSmall)
        Text("插件在独立应用 UID 中运行，只申请联网权限；控制服务仅接受同签名宿主。安装或恢复前会结束 HTTP(S) 调试，系统已安装的 CA 仍需手动移除。")
        Text(installed?.let { "已安装 ${it.versionName}（构建 ${HttpDebugPackagePolicy.versionCode(it)}）" } ?: "未安装插件")
        installed?.let { info ->
            snapshot.revoked["android/http-debug/${HttpDebugPackagePolicy.versionCode(info)}"]?.let { reason -> Text("此版本已撤销并禁止启动：$reason", color = MaterialTheme.colorScheme.error) }
        }
        if (snapshot.trustedKeyCount == 0) Text("此应用尚未配置发布者目录公钥，在线安装关闭。可以返回调试页明确选择同签名本地 APK。", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(url, { url = it }, enabled = !occupied, label = { Text("HTTPS 签名目录地址") }, modifier = Modifier.fillMaxWidth())
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = !occupied && snapshot.trustedKeyCount > 0, onClick = { action {
                PluginTrustStore.refresh(url); preferences.edit().putString("url", url).apply(); message = "已更新签名目录。"
            } }) { Text("读取目录") }
            OutlinedButton(enabled = !occupied && snapshot.trustedKeyCount > 0, onClick = { catalogFile.launch(arrayOf("application/json", "application/octet-stream", "*/*")) }) { Text("选择目录文件") }
        }
        snapshot.catalog?.let { catalog ->
            Text("目录序号 ${catalog.sequence} · " + if (catalog.fresh()) "有效" else "已过期，请刷新后下载新版本")
            Text("离线时可使用此前验证的已安装/缓存版本；新的撤销信息需重新读取目录。", style = MaterialTheme.typography.bodySmall)
            val releases = catalog.releases.filter { it.platform == "android" && it.id == "http-debug" && it.abi in Build.SUPPORTED_ABIS }
                .sortedBy { Build.SUPPORTED_ABIS.indexOf(it.abi) }.distinctBy { it.build }.sortedByDescending { it.build }
            if (releases.isEmpty()) Text("目录中没有此设备架构的调试插件。")
            releases.forEach { release -> Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                Text("${release.version} · ${release.abi} · ${release.bytes / 1024 / 1024} MiB", style = MaterialTheme.typography.titleSmall)
                Text("权限：联网、插件私有文件、用户选择域名的 HTTPS 调试。", style = MaterialTheme.typography.bodySmall)
                val revoked = snapshot.revoked[release.revocationKey]
                if (revoked != null) Text("已撤销：$revoked", color = MaterialTheme.colorScheme.error)
                else if (!PluginTrustStore.compatible(release)) Text("与当前应用、核心或系统版本不兼容。")
                Button(enabled = !occupied && catalog.fresh() && PluginTrustStore.compatible(release) &&
                    (installed == null || release.build >= HttpDebugPackagePolicy.versionCode(requireNotNull(installed))), onClick = { action {
                    val file = PluginTrustStore.prepareInstall(release)
                    HttpDebug.stop(); install(file)
                } }) { Text(if (installed == null) "验证并安装" else "验证并更新") }
            } } }
        }
        if (snapshot.cached.isNotEmpty()) {
            Text("已验证的恢复文件", style = MaterialTheme.typography.titleMedium)
            snapshot.cached.forEach { cached -> OutlinedButton(enabled = !occupied && PluginTrustStore.compatible(cached.release), onClick = { confirm = cached }, modifier = Modifier.fillMaxWidth()) {
                Text("恢复 ${cached.release.version}（构建 ${cached.release.build}）")
            } }
        }
        pending?.let { candidate -> OutlinedButton(enabled = !occupied, onClick = { action {
            val file = PluginTrustStore.prepareCached(candidate)
            HttpDebug.stop(); install(file)
        } }) { Text("继续系统安装") } }
        TextButton(enabled = !occupied, onClick = { context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${HttpDebug.PACKAGE}"))) }) { Text("系统插件管理") }
        if (occupied) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            if (snapshot.total > 0) Text("${snapshot.received / 1024} / ${snapshot.total / 1024} KiB")
        }
        if (message.isNotEmpty()) Text(message)
        if (snapshot.error.isNotEmpty()) Text(snapshot.error, color = MaterialTheme.colorScheme.error)
    }
    confirm?.let { candidate ->
        val older = installed?.let { HttpDebugPackagePolicy.versionCode(it) > candidate.release.build } == true
        AlertDialog(onDismissRequest = { if (!occupied) confirm = null }, title = { Text("恢复已验证版本") }, text = {
            Text(if (older) "Android 不允许直接降低版本号。先停止调试并由你确认卸载插件，再安装缓存版本；插件数据与私钥会被删除，系统 CA 需另外移除。" else "将停止当前调试并验证缓存文件，再由系统确认安装。不会自动启用流量截获。")
        }, confirmButton = { TextButton(enabled = !occupied, onClick = { confirm = null; action {
            val file = PluginTrustStore.prepareCached(candidate); HttpDebug.stop()
            if (older) {
                recovery = candidate
                uninstall.launch(Intent(Intent.ACTION_DELETE, Uri.parse("package:${HttpDebug.PACKAGE}")).putExtra(Intent.EXTRA_RETURN_RESULT, true))
            } else install(file)
        } }) { Text(if (older) "停止并卸载以恢复" else "确认恢复") } }, dismissButton = { TextButton(enabled = !occupied, onClick = { confirm = null }) { Text("取消") } })
    }
}
