package io.sbeasy.android

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.sbeasy.android.core.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

@Composable
internal fun CaptureScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val saved = remember { PacketCapture.config() }
    val control by CoreGraph.repository.state.collectAsState()
    val managed = control.mode == ClientMode.MANAGED && control.enrollment != null
    var enabled by remember { mutableStateOf(saved.enabled) }
    var packages by remember { mutableStateOf(saved.packages.joinToString("\n")) }
    var domains by remember { mutableStateOf(saved.domains.joinToString("\n")) }
    var hosts by remember { mutableStateOf(saved.hosts.joinToString("\n")) }
    var bpf by remember { mutableStateOf(saved.bpf) }
    var fileKB by remember { mutableStateOf(saved.fileKB.toString()) }
    var quotaMB by remember { mutableStateOf(saved.quotaMB.toString()) }
    var rotateSeconds by remember { mutableStateOf(saved.rotateSeconds.toString()) }
    var uploadSeconds by remember { mutableStateOf(saved.uploadSeconds.toString()) }
    var auto by remember { mutableStateOf(saved.autoUpload) }
    var wifi by remember { mutableStateOf(saved.wifiOnly) }
    var deleteUploaded by remember { mutableStateOf(saved.deleteAfterUpload) }
    var message by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var files by remember { mutableStateOf(emptyList<CaptureFile>()) }
    var exporting by remember { mutableStateOf<CaptureFile?>(null) }
    var pickingApp by remember { mutableStateOf(false) }
    var visibleFiles by remember { mutableIntStateOf(100) }
    var deleting by remember { mutableStateOf<CaptureFile?>(null) }
    val exporter = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.tcpdump.pcap")) { uri ->
        val file = exporting
        if (uri != null && file != null) scope.launch {
            message = runCatching { withContext(Dispatchers.IO) {
                requireNotNull(context.contentResolver.openOutputStream(uri)).use { output -> file.file.inputStream().use { it.copyTo(output) } }
            }; "PCAP 已导出" }.getOrElse { it.message.orEmpty() }
        }
    }
    LaunchedEffect(Unit) {
        while (true) {
            withContext(Dispatchers.IO) {
                files = PacketCapture.files(CoreGraph.repository.state.value.enrollment)
                val native = runCatching { JSONObject(PacketCapture.nativeStatus()) }.getOrDefault(JSONObject())
                status = "${if (PacketCapture.config().enabled && RuntimeBridge.control != null && PacketCapture.runtimeError.isEmpty()) "采集中" else "未采集"} · 已采集 ${native.optLong("packets")} 包 · BPF 排除 ${native.optLong("filtered")} 包 · 丢弃/未识别 ${native.optLong("dropped")} 包\n${native.optString("error")}\n${PacketCapture.runtimeError}\n${PacketCapture.uploadStatus}".trim()
            }
            delay(2000)
        }
    }
    fun number(raw: String): Int = raw.toIntOrNull() ?: throw IllegalArgumentException("大小和间隔请填写整数")
    fun list(raw: String) = raw.split(Regex("[\\s,，]+" )).filter { it.isNotBlank() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("原始流量采集 · PCAP", style = MaterialTheme.typography.titleLarge)
        Text("仅采集经过本机 VPN 的 TCP/UDP 流量。条件之间为“或”；域名包含子域名，host/IP 精确匹配。HTTPS 保持加密；无法识别域名的连接请用 App 或 IP 筛选。", style = MaterialTheme.typography.bodySmall)
        CaptureToggle("启用采集", enabled) { enabled = it }
        OutlinedButton(onClick = { pickingApp = true }, modifier = Modifier.fillMaxWidth()) { Text("选择已安装的应用") }
        if (list(packages).isEmpty()) Text("尚未选择应用；也可只按域名、host 或 BPF 采集。", style = MaterialTheme.typography.bodySmall)
        CaptureSelectedApps(list(packages)) { removed -> packages = list(packages).filterNot { it == removed }.joinToString("\n") }
        OutlinedTextField(domains, { domains = it }, label = { Text("域名（含子域名）") }, placeholder = { Text("example.com") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(hosts, { hosts = it }, label = { Text("精确 host / IP") }, placeholder = { Text("api.example.com") }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(bpf, { bpf = it }, label = { Text("BPF 抓包过滤（可选）") }, placeholder = { Text("tcp port 443 or udp port 53") }, modifier = Modifier.fillMaxWidth())
        Text("BPF 与上方已选条件同时满足才保存；只填 BPF 时筛选全部 VPN TCP/UDP 流量。支持标准 libpcap 抓包语法，不是 tcp.port == 443 这类显示过滤语法。IP 为原始包中的地址（可能是 FakeIP）；按网站筛选请用上方域名。", style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { bpf = "tcp port 443" }) { Text("HTTPS") }
            TextButton(onClick = { bpf = "udp port 53" }) { Text("DNS") }
            TextButton(onClick = { bpf = "not udp port 443" }) { Text("排除 QUIC") }
        }
        OutlinedButton(enabled = !busy, onClick = { busy = true; scope.launch {
            message = runCatching { withContext(Dispatchers.IO) { PacketCapture.validateFilter(bpf) }; "BPF 语法有效" }.getOrElse { "BPF 校验失败：${it.message}" }
            busy = false
        } }) { Text("检查 BPF 语法") }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(fileKB, { fileKB = it }, label = { Text("单文件 KB") }, modifier = Modifier.weight(1f), singleLine = true)
            OutlinedTextField(quotaMB, { quotaMB = it }, label = { Text("本地上限 MB") }, modifier = Modifier.weight(1f), singleLine = true)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(rotateSeconds, { rotateSeconds = it }, label = { Text("文件轮转秒数") }, modifier = Modifier.weight(1f), singleLine = true)
            OutlinedTextField(uploadSeconds, { uploadSeconds = it }, label = { Text("上传间隔秒数") }, modifier = Modifier.weight(1f), singleLine = true)
        }
        if (managed) CaptureToggle("自动上传到已注册的服务器", auto) { auto = it }
        else Text("独立模式仅保留本机文件，可手动导出。", style = MaterialTheme.typography.bodySmall)
        CaptureToggle("仅 Wi-Fi 上传（手动上传也适用）", wifi) { wifi = it }
        CaptureToggle("上传成功后删除本地文件", deleteUploaded) { deleteUploaded = it }
        Text("保存配置会重启正在运行的 VPN。自动上传随 VPN 服务运行；停止 VPN 后可手动上传。空间满后暂停采集。", style = MaterialTheme.typography.bodySmall)
        Button(enabled = !busy, onClick = {
            busy = true
            scope.launch {
                message = runCatching {
                    CoreGraph.repository.saveCaptureConfiguration(CaptureConfig(enabled, list(packages), list(domains), list(hosts),
                        number(fileKB), number(quotaMB), number(rotateSeconds), auto && managed, wifi, number(uploadSeconds), deleteUploaded, bpf))
                    "配置已保存"
                }.getOrElse { "保存失败：${it.message}" }
                busy = false
            }
        }) { Text("保存并应用") }
        Text(status, style = MaterialTheme.typography.bodySmall)
        if (message.isNotBlank()) Text(message)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(enabled = !busy, onClick = { scope.launch { withContext(Dispatchers.IO) { PacketCapture.rotate() } } }) { Text("结束当前文件") }
            OutlinedButton(enabled = !busy && managed, onClick = { busy = true; scope.launch {
                message = runCatching { CoreGraph.repository.uploadCaptures(); PacketCapture.uploadStatus }.getOrElse { it.message.orEmpty() }
                busy = false
            } }) { Text("上传待传文件") }
        }
        Text("本地文件 ${files.size} 个 · ${files.sumOf { it.file.length() } / 1024} KB", style = MaterialTheme.typography.titleMedium)
        files.take(visibleFiles).forEach { entry ->
            Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(10.dp)) {
                Text(entry.file.name, style = MaterialTheme.typography.bodySmall)
                Text("${entry.file.length()/1024} KB · ${if (entry.uploaded) "已上传" else "待上传"}")
                Row {
                    TextButton(onClick = { exporting = entry; exporter.launch(entry.file.name) }) { Text("导出") }
                    TextButton(onClick = { deleting = entry }) { Text("删除") }
                }
            } }
        }
        if (files.size > visibleFiles) TextButton(onClick = { visibleFiles += 100 }) { Text("显示更多文件") }
    }
    if (pickingApp) ApplicationPicker(list(packages), onDismiss = { pickingApp = false }) { selected ->
        packages = selected.sorted().joinToString("\n")
        pickingApp = false
    }
    deleting?.let { entry -> AlertDialog(onDismissRequest = { deleting = null }, title = { Text("删除此 PCAP？") },
        text = { Text(if (entry.uploaded) "仅删除本地文件。" else "此文件尚未上传，删除后无法恢复。") },
        confirmButton = { TextButton(onClick = { deleting = null; scope.launch { message = runCatching { PacketCapture.delete(entry); "已删除" }.getOrElse { it.message.orEmpty() } } }) { Text("删除") } },
        dismissButton = { TextButton(onClick = { deleting = null }) { Text("取消") } }) }
}

@Composable
private fun CaptureSelectedApps(packages: List<String>, onRemove: (String) -> Unit) {
    val context = LocalContext.current
    val labels by produceState<Map<String, String>>(emptyMap(), packages) {
        value = withContext(Dispatchers.IO) { packages.associateWith { name ->
            runCatching { @Suppress("DEPRECATION")
                context.packageManager.getApplicationLabel(context.packageManager.getApplicationInfo(name, 0)).toString()
            }.getOrDefault("未安装的应用：$name")
        } }
    }
    packages.forEach { name ->
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(labels[name] ?: "正在读取应用名称…", modifier = Modifier.weight(1f).padding(top = 12.dp))
            TextButton(onClick = { onRemove(name) }) { Text("移除") }
        }
    }
}

@Composable
private fun CaptureToggle(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, modifier = Modifier.weight(1f).padding(top = 12.dp))
        Switch(value, onCheckedChange = onChange)
    }
}
