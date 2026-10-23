package io.sbeasy.android

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.sbeasy.android.core.CaptureSession
import io.sbeasy.android.core.HttpDebug
import io.sbeasy.android.core.PacketCapture
import kotlinx.coroutines.launch

@Composable
internal fun CaptureToolsScreen() {
    val enabled by CaptureSession.enabled.collectAsState()
    val debug by HttpDebug.state.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var section by remember { mutableIntStateOf(0) }
    var error by remember { mutableStateOf("") }
    var stopping by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        if (debug.caFingerprint.isNotEmpty()) {
            Text("已记录调试 CA；结束后请在系统安全设置移除已安装的证书。", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.bodySmall)
            Row(Modifier.padding(horizontal = 8.dp)) {
                TextButton(onClick = { context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) }) { Text("管理系统证书") }
                TextButton(onClick = { scope.launch { runCatching { HttpDebug.verifyCertificateRemoved() }.onFailure { error = it.message.orEmpty() } } }) { Text("检查 CA 已移除") }
            }
        }
        if (error.isNotBlank()) Text(error, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.error)
        if (!enabled) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("可选流量采集", style = MaterialTheme.typography.headlineSmall)
                Text("采集可能包含登录令牌与私密内容。仅对自有或已获授权的流量启用；默认保留在本机。PCAP 保留加密流量，HTTPS 调试需要另外安装本机插件和 CA。")
                Text("每次进程重启或 VPN 停止后均关闭采集，原有文件保留。此功能仍需在你的设备上验证。")
                Button(onClick = { CaptureSession.authorize() }) { Text("启用本次采集会话") }
            }
        } else {
            Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp)) {
                TextButton(onClick = { section = 0 }) { Text("PCAP") }
                TextButton(onClick = { section = 1 }) { Text("HTTP(S) 调试") }
                Spacer(Modifier.weight(1f))
                TextButton(enabled = !stopping, onClick = { scope.launch {
                    stopping = true
                    try { HttpDebug.stop(); PacketCapture.endSession() }
                    catch (failure: Exception) { error = failure.message.orEmpty() }
                    finally { stopping = false }
                } }) { Text("停止全部采集") }
            }
            Box(Modifier.weight(1f)) { if (section == 0) CaptureScreen() else HttpDebugScreen() }
        }
    }
}
