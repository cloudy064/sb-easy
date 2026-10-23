package io.sbeasy.android

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
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
import io.sbeasy.android.core.HttpDebug
import io.sbeasy.android.core.HttpDebugPackagePolicy
import kotlinx.coroutines.*
import java.io.File

@Composable
internal fun HttpDebugScreen() {
    var managePlugins by remember { mutableStateOf(false) }
    if (managePlugins) { PluginManagerScreen(onBack = { managePlugins = false }); return }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val state by HttpDebug.state.collectAsState()
    var installed by remember { mutableStateOf(HttpDebug.installed(context)) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var domains by remember { mutableStateOf(state.domains.joinToString("\n")) }
    var certificate by remember { mutableStateOf<ByteArray?>(null) }
    var staged by remember { mutableStateOf<File?>(null) }
    var confirmClear by remember { mutableStateOf(false) }
    fun action(block: suspend () -> Unit) { scope.launch {
        busy = true; error = ""
        try { block() }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (failure: Exception) { error = failure.message.orEmpty() }
        finally { busy = false }
    } }
    suspend fun install(file: File) {
        withContext(Dispatchers.IO) { HttpDebugPackagePolicy.inspect(context, file, BuildConfig.VERSION_NAME) }
        HttpDebug.stop()
        if (Build.VERSION.SDK_INT >= 26 && !context.packageManager.canRequestPackageInstalls()) {
            context.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}")))
        } else {
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.httpdebug.files", file)
            context.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
        }
    }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) action { staged = HttpDebugInstaller.stage(context, uri); install(requireNotNull(staged)) }
    }
    val saveCertificate = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/x-x509-ca-cert")) { uri ->
        if (uri != null) action { withContext(Dispatchers.IO) {
            requireNotNull(context.contentResolver.openOutputStream(uri)) { "无法写入证书" }.use { it.write(requireNotNull(certificate)) }
        } }
    }
    LaunchedEffect(Unit) { while (true) {
        installed = HttpDebug.installed(context)
        if (!busy) runCatching { HttpDebug.refresh() }.onFailure { error = it.message.orEmpty() }
        delay(2000)
    } }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("HTTP(S) 调试", style = MaterialTheme.typography.headlineSmall)
        OutlinedButton(onClick = { managePlugins = true }, enabled = !busy) { Text("插件目录、更新与恢复") }
        Text("mitmproxy 在本机查看、编辑、断点与重放请求，支持 HAR 导出。安装插件不影响普通代理；只有明确选择域名并开始后才会拦截。")
        if (error.isNotBlank() || state.error.isNotBlank()) Text(error.ifBlank { state.error }, color = MaterialTheme.colorScheme.error)
        if (!installed) {
            Text("安装插件 1.0.1+（ARM64 / x86_64）", style = MaterialTheme.typography.titleMedium)
            Text("选择与主应用同一签名的官方插件 APK。应用会检查包名、版本和签名，随后由 Android 确认安装。旧版插件需要升级。")
            Button(enabled = !busy, onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream")) }) { Text("选择并验证插件 APK") }
            staged?.let { file -> OutlinedButton(enabled = !busy, onClick = { action { install(file) } }) { Text("继续安装已验证插件") } }
        } else {
            Button(enabled = !busy && state.phase == "stopped", onClick = { action { HttpDebug.start(context) } }) { Text("启动本机引擎") }
            Text("引擎：${state.phase}${if (state.attached) " · 已接入所选域名" else ""}")
            Text("保存 CA 后，在系统安全设置安装为 CA 证书。用户 CA 不被所有应用信任；证书固定的应用可能失败。本工具不绕过证书固定。")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = !busy && state.phase == "running", onClick = { action {
                    certificate = HttpDebug.certificate(); saveCertificate.launch("sb-easy-debug-ca.cer")
                } }) { Text("保存 CA") }
                TextButton(onClick = { context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) }) { Text("系统安全设置") }
            }
            if (state.caFingerprint.isNotBlank()) Text("CA SHA-256：${state.caFingerprint}", style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(value = domains, onValueChange = { domains = it }, enabled = !state.attached && !busy,
                label = { Text("调试域名，以空格或换行分隔") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
            Text("仅捕获所选域名（含子域名）的 TCP 80/443。中心、私网/WireGuard及已设置应用分流的应用继续遵循原规则，不参与 HTTPS 拦截。浏览器域名出口保持不变。所选域名的 UDP/443 会拒绝，依赖 HTTP/3 且不能回退的应用可能失败。", style = MaterialTheme.typography.bodySmall)
            Button(enabled = !busy && state.phase == "running" && !state.attached && domains.isNotBlank(), onClick = { action { HttpDebug.attach(domains) } }) { Text("开始调试所选域名") }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(enabled = !busy && state.phase == "running", onClick = { action { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(state.url))) } }) { Text("会话窗口") }
                OutlinedButton(enabled = !busy && state.phase == "running", onClick = { action {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(state.url.replace("/?token=", "/sbeasy.har?token="))))
                } }) { Text("导出 HAR") }
            }
            OutlinedButton(enabled = !busy && state.phase != "stopped", onClick = { action { HttpDebug.stop() } }) { Text("停止并恢复普通代理") }
            OutlinedButton(enabled = !busy, onClick = { confirmClear = true }) { Text("清理插件 CA 私钥与会话") }
        }
        TextButton(enabled = !busy && state.phase == "stopped", onClick = { context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${HttpDebug.PACKAGE}"))) }) { Text("管理或卸载插件") }
        Text("停止引擎会关闭监听、清空会话并删除插件本地 CA 私钥；异常退出遗留的私钥会在下次启动前删除。系统已安装的 CA 仍需在安全设置中移除，然后检查清理状态。已导出的证书和 HAR/PCAP 文件由你管理。", style = MaterialTheme.typography.bodySmall)
    }
    if (confirmClear) AlertDialog(onDismissRequest = { confirmClear = false }, title = { Text("停止调试并删除本机 CA 私钥？") },
        text = { Text("旧 CA 之后不能用于解密新会话。系统中已安装的 CA 仍需在安全设置中手动移除。") },
        confirmButton = { TextButton(onClick = { confirmClear = false; action { HttpDebug.clearLocalAuthority(context) } }) { Text("停止并清理") } },
        dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("取消") } })
}
