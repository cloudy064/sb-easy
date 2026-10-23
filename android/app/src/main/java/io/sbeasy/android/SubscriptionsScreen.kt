package io.sbeasy.android

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.sbeasy.android.core.ClientMode
import io.sbeasy.android.core.CoreGraph
import io.sbeasy.android.core.LocalSubscription
import io.sbeasy.android.core.VpnPhase
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

@Composable
internal fun SubscriptionsScreen(mode: ClientMode, phase: VpnPhase) {
    val subscriptions by CoreGraph.repository.subscriptions.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var editing by remember { mutableStateOf<LocalSubscription?>(null) }
    var showEditor by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<LocalSubscription?>(null) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    val disconnected = phase in setOf(VpnPhase.DISCONNECTED, VpnPhase.ERROR)
    LazyColumn(contentPadding = PaddingValues(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("本机订阅", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                    Text(if (mode == ClientMode.STANDALONE) "独立模式 · 无需中心。导入节点后即可连接；已有配置可离线启动。" else "受管模式正在使用中心配置。本机订阅独立保存，切换到独立模式后生效。")
                    Text("支持订阅 URL、分享链接、Clash YAML、sing-box JSON 和 Base64。只导入代理节点，源文件中的路由、DNS、分组与脚本不会导入。独立模式默认代理公网流量、直连私网，服务分组可在代理页编辑。", style = MaterialTheme.typography.bodySmall)
                    Button(onClick = { editing = null; showEditor = true }, enabled = !busy) { Text("添加订阅或粘贴节点") }
                    if (mode == ClientMode.MANAGED) OutlinedButton(onClick = {
                        scope.launch { runCatching { CoreGraph.repository.switchMode(ClientMode.STANDALONE) }.onFailure { message = it.message } }
                    }, enabled = disconnected && !busy) { Text(if (disconnected) "切换到独立模式" else "先断开 VPN 再切换模式") }
                    Text("自动更新最短 15 分钟；Android 休眠/省电策略可能延迟任务。更新失败时保留原节点，已选出口与分组保存在本机。", style = MaterialTheme.typography.bodySmall)
                    message?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
                }
            }
        }
        items(subscriptions, key = { it.id }) { record ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Text(record.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text("${record.nodes.size} 个节点 · ${record.format} · ${if (record.remote) if (record.intervalMinutes > 0) "每 ${record.intervalMinutes} 分钟更新" else "手动更新" else "本机粘贴"}")
                    Text("最近成功：${if (record.lastSuccess > 0) DateFormat.getDateTimeInstance().format(Date(record.lastSuccess)) else "尚未更新"}", style = MaterialTheme.typography.bodySmall)
                    record.quota.remaining?.let { remaining ->
                        Text("套餐剩余 ${subscriptionBytes(remaining)} / ${subscriptionBytes(record.quota.total ?: 0)}")
                    }
                    record.quota.expire?.let { expire ->
                        Text("${if (record.quota.expired(System.currentTimeMillis())) "已到期" else "到期"}：${DateFormat.getDateTimeInstance().format(Date(expire * 1000))}", color = if (record.quota.expired(System.currentTimeMillis())) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
                    }
                    if (record.quota.total == null && record.quota.expire == null) Text("提供方未返回套餐余量或到期信息", style = MaterialTheme.typography.bodySmall)
                    record.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                    if (record.issues.isNotEmpty()) {
                        Text("跳过 ${record.issues.size} 项", color = MaterialTheme.colorScheme.error)
                        record.issues.forEach { Text("第 ${it.index} 项：${it.reason}", style = MaterialTheme.typography.bodySmall) }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        if (record.remote) TextButton(onClick = {
                            busy = true; message = null
                            scope.launch {
                                runCatching { CoreGraph.repository.refreshSubscriptions(force = true, onlyId = record.id) }
                                    .onFailure { message = "刷新失败，已保留原配置" }
                                busy = false
                            }
                        }, enabled = !busy) { Text("刷新") }
                        TextButton(onClick = { editing = record; showEditor = true }, enabled = !busy) { Text("编辑") }
                        TextButton(onClick = { pendingDelete = record }, enabled = !busy) { Text("删除") }
                    }
                }
            }
        }
    }
    if (showEditor) SubscriptionEditor(editing, onDismiss = { showEditor = false }, onSaved = { report ->
        showEditor = false; message = report
    })
    pendingDelete?.let { record ->
        AlertDialog(onDismissRequest = { pendingDelete = null }, title = { Text("删除 ${record.name}？") },
            text = { Text("将删除本机保存的订阅地址和节点。请先为正在使用此订阅的分组选好其他出口。") },
            confirmButton = { TextButton(onClick = {
                pendingDelete = null; busy = true
                scope.launch { runCatching { CoreGraph.repository.removeSubscription(record.id) }.onFailure { message = it.message }; busy = false }
            }) { Text("删除") } }, dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text("取消") } })
    }
}

@Composable
private fun SubscriptionEditor(record: LocalSubscription?, onDismiss: () -> Unit, onSaved: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf(record?.name.orEmpty()) }
    var source by remember { mutableStateOf(record?.source.orEmpty()) }
    var remote by remember { mutableStateOf(record?.remote ?: true) }
    var interval by remember { mutableStateOf((record?.intervalMinutes ?: 360).toString()) }
    var allowInsecure by remember { mutableStateOf(record?.allowInsecure ?: false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(onDismissRequest = { if (!busy) onDismiss() }, title = { Text(if (record == null) "添加本机订阅" else "编辑订阅") }, text = {
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item { OutlinedTextField(name, { name = it }, label = { Text("名称") }, modifier = Modifier.fillMaxWidth(), singleLine = true) }
            item { Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { TextButton(onClick = { remote = true }, enabled = !busy) { Text(if (remote) "● 订阅 URL" else "订阅 URL") }; TextButton(onClick = { remote = false }, enabled = !busy) { Text(if (!remote) "● 粘贴内容" else "粘贴内容") } } }
            item { OutlinedTextField(source, { source = it }, label = { Text(if (remote) "HTTPS 订阅地址" else "分享链接 / YAML / JSON / Base64") }, modifier = Modifier.fillMaxWidth(), minLines = 3, maxLines = 8) }
            if (remote) {
                item { OutlinedTextField(interval, { interval = it }, label = { Text("更新间隔（分钟，0 关闭）") }, singleLine = true, modifier = Modifier.fillMaxWidth()) }
                item { Row { Column(Modifier.weight(1f)) { Text("允许局域网 HTTP"); Text("HTTP 会明文传输订阅凭据", style = MaterialTheme.typography.bodySmall) }; Switch(allowInsecure, { allowInsecure = it }) } }
            }
            item { Text("订阅原文和地址使用 Android Keystore 加密保存；运行配置保存在应用私有目录，不会发送到中心或第三方转换服务。", style = MaterialTheme.typography.bodySmall) }
            error?.let { item { Text(it, color = MaterialTheme.colorScheme.error) } }
        }
    }, confirmButton = {
        TextButton(onClick = {
            busy = true; error = null
            scope.launch {
                runCatching { CoreGraph.repository.saveSubscription(record?.id, name, source, remote, if (remote) interval.toIntOrNull() ?: -1 else 0, allowInsecure) }
                    .onSuccess { onSaved(it.summary) }
                    .onFailure { error = it.message ?: "订阅导入失败，原配置保持可用" }
                busy = false
            }
        }, enabled = !busy && name.isNotBlank() && source.isNotBlank()) { Text(if (busy) "校验与保存中…" else "导入并保存") }
    }, dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("取消") } })
}

private fun subscriptionBytes(value: Long): String = when {
    value >= 1024L * 1024 * 1024 -> "%.2f GB".format(value / (1024.0 * 1024 * 1024))
    value >= 1024L * 1024 -> "%.1f MB".format(value / (1024.0 * 1024))
    else -> "$value B"
}
