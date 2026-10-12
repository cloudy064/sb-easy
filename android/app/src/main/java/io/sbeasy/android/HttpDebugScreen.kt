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
import kotlinx.coroutines.*
import java.io.File
import java.net.URL
import java.security.MessageDigest

@Composable
internal fun HttpDebugScreen() {
    val context = LocalContext.current; val scope = rememberCoroutineScope()
    val state by HttpDebug.state.collectAsState()
    var installed by remember { mutableStateOf(HttpDebug.installed(context)) }
    var busy by remember { mutableStateOf(false) }; var error by remember { mutableStateOf("") }
    var domains by remember { mutableStateOf(state.domains.joinToString("\n")) }
    var certificate by remember { mutableStateOf<ByteArray?>(null) }
    val saveCertificate = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/x-x509-ca-cert")) { uri ->
        if (uri != null) scope.launch {
            runCatching { withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri)?.use { it.write(requireNotNull(certificate)) } ?: error("无法写入证书") } }
                .onFailure { error = it.message.orEmpty() }
        }
    }
    fun action(block: suspend () -> Unit) { scope.launch { busy = true; error = ""; try { block() } catch (e: Exception) { error = e.message.orEmpty() } finally { busy = false } } }
    LaunchedEffect(Unit) { while (true) { installed = HttpDebug.installed(context); if (!busy) runCatching { HttpDebug.refresh() }.onFailure { error = it.message.orEmpty() }; delay(2000) } }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("HTTP(S) 抓包", style = MaterialTheme.typography.headlineSmall)
        Text("由 mitmproxy 驱动，在手机本地查看、修改和重放明文请求。无需电脑，基础代理不依赖此插件。")
        if (error.isNotBlank() || state.error.isNotBlank()) Text(error.ifBlank { state.error }, color = MaterialTheme.colorScheme.error)
        if (!installed) {
            Text("扩展商店 · HTTP(S) 抓包 1.0.0", style = MaterialTheme.typography.titleMedium)
            Text("独立 APK，支持 ARM64 / x86_64。安装需要系统确认，证书与会话保存在本机。")
            Button(enabled = !busy, onClick = { action {
                val artifact = HttpDebugStore.artifact(Build.SUPPORTED_ABIS.toList())
                val apk = withContext(Dispatchers.IO) {
                    val directory = File(context.cacheDir, "http-debug-install").apply { mkdirs() }
                    val target = File(directory, "http-debug.apk")
                    val connection = URL(artifact.url).openConnection().apply { connectTimeout = 15_000; readTimeout = 30_000 }
                    try {
                        val digest = MessageDigest.getInstance("SHA-256"); var length = 0L
                        connection.getInputStream().use { input -> target.outputStream().use { output ->
                            val buffer = ByteArray(65536)
                            while (true) { val count = input.read(buffer); if (count < 0) break; length += count; check(length <= artifact.size) { "插件大小不匹配" }; digest.update(buffer, 0, count); output.write(buffer, 0, count) }
                        } }
                        check(length == artifact.size && digest.digest().joinToString("") { "%02x".format(it) } == artifact.sha256) { "插件完整性校验失败" }
                        target
                    } catch (failure: Throwable) { target.delete(); throw failure }
                }
                val uri = FileProvider.getUriForFile(context, "${context.packageName}.httpdebug.files", apk)
                context.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
            } }) { Text(if (busy) "正在准备…" else "下载并安装插件") }
            return@Column
        }
        Text("1 · 启动本机引擎", style = MaterialTheme.typography.titleMedium)
        TextButton(enabled = !busy && state.phase == "stopped", onClick = { context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${HttpDebug.PACKAGE}"))) }) { Text("管理或卸载插件") }
        Button(enabled = !busy && state.phase == "stopped", onClick = { action { HttpDebug.start(context) } }) { Text(if (state.phase == "stopped") "启动引擎" else "引擎：${state.phase}") }
        Text("2 · 安装抓包证书", style = MaterialTheme.typography.titleMedium)
        Text("先保存证书，再到系统安全设置安装为 CA 证书。许多安卓应用不信任用户证书，或使用证书固定；这些连接无法保证解密，请在会话窗口查看错误。")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(enabled = !busy && state.phase == "running", onClick = { action { certificate = HttpDebug.certificate(); saveCertificate.launch("sb-easy-capture-ca.cer") } }) { Text("保存 CA 证书") }
            TextButton(onClick = { context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) }) { Text("系统安全设置") }
        }
        Text("3 · 选择域名", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(value = domains, onValueChange = { domains = it }, enabled = !state.attached, label = { Text("抓包域名，以空格或换行分隔") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        Text("包含子域名，只抓取 80/443 端口。开始与停止会自动重载本地 VPN 配置；出口继续按域名分流。所选域名的 QUIC 会被拒绝，促使应用回退到 TCP。")
        Button(enabled = !busy && state.phase == "running" && !state.attached && domains.isNotBlank(), onClick = { action { HttpDebug.attach(domains) } }) { Text(if (state.attached) "正在抓包" else "开始抓包") }
        Button(enabled = !busy && state.phase == "running", onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(state.url))) }) { Text("打开会话窗口") }
        OutlinedButton(enabled = !busy && state.phase == "running", onClick = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(state.url.replace("/?token=", "/sbeasy.har?token=")))) }) { Text("导出 HAR") }
        OutlinedButton(enabled = !busy && state.phase != "stopped", onClick = { action { HttpDebug.stop() } }) { Text("停止并恢复普通代理") }
        Text("会话窗口提供请求/响应查看、过滤、编辑、断点、重放与 HAR 导出。最多保留约 500 个已完成会话，超过 2 MB 的正文按流转发而不保留，单条消息上限 32 MB。停止引擎会清空会话，证书保留；可在系统安全设置移除。")
    }
}
