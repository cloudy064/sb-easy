package io.sbeasy.android

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.sbeasy.android.core.AutomaticSelection
import io.sbeasy.android.core.HealthPolicy
import io.sbeasy.android.core.ProxyItemSnapshot

@Composable
internal fun HealthPolicyEditor(initial: HealthPolicy, busy: Boolean, saveError: String?, onDismiss: () -> Unit, onSave: (HealthPolicy) -> Unit) {
    var enabled by remember { mutableStateOf(initial.enabled) }
    var url by remember { mutableStateOf(initial.probeUrl) }
    var interval by remember { mutableStateOf(initial.intervalSeconds.toString()) }
    var timeout by remember { mutableStateOf(initial.timeoutMillis.toString()) }
    var tolerance by remember { mutableStateOf(initial.toleranceMillis.toString()) }
    var selection by remember { mutableStateOf(initial.selection) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("健康探测与自动切换") }, text = {
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item { Row(verticalAlignment = Alignment.CenterVertically) { Text("后台定期探测", modifier = Modifier.weight(1f)); Switch(enabled, { enabled = it }, enabled = !busy) } }
            item { OutlinedTextField(url, { url = it }, label = { Text("HTTPS 探测网址") }, modifier = Modifier.fillMaxWidth(), enabled = !busy) }
            item { OutlinedTextField(interval, { interval = it }, label = { Text("间隔（秒，30–86400）") }, singleLine = true, modifier = Modifier.fillMaxWidth(), enabled = !busy) }
            item { OutlinedTextField(timeout, { timeout = it }, label = { Text("超时（毫秒，500–30000）") }, singleLine = true, modifier = Modifier.fillMaxWidth(), enabled = !busy) }
            item { OutlinedTextField(tolerance, { tolerance = it }, label = { Text("择优容差（毫秒，0–10000）") }, singleLine = true, modifier = Modifier.fillMaxWidth(), enabled = !busy) }
            item {
                AutomaticSelection.entries.forEach { option ->
                    Row(Modifier.fillMaxWidth().clickable(enabled = !busy) { selection = option }, verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selection == option, onClick = null, enabled = !busy)
                        Text(if (option == AutomaticSelection.FAILOVER) "仅故障时切换，优先保持出口" else "自动择优，改善超过容差才切换")
                    }
                }
            }
            item { Text("自动切换只使用各组明确选择的候选池，不会回退直连。固定节点只检测并提示故障，始终保持出口。自动组需要启用后台探测；系统省电可能延迟探测。", style = MaterialTheme.typography.bodySmall) }
            (error ?: saveError)?.let { item { Text(it, color = MaterialTheme.colorScheme.error) } }
        }
    }, confirmButton = { TextButton(onClick = {
        runCatching {
            HealthPolicy(enabled, url.trim(), interval.toIntOrNull() ?: -1, timeout.toIntOrNull() ?: -1,
                tolerance.toIntOrNull() ?: -1, selection).also { it.validate() }
        }.onSuccess(onSave).onFailure { error = it.message }
    }, enabled = !busy) { Text(if (busy) "保存中…" else "保存") } },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("取消") } })
}

@Composable
internal fun AutomaticPoolEditor(name: String, initial: List<String>, nodes: List<ProxyItemSnapshot>, busy: Boolean,
    error: String?, onDismiss: () -> Unit, onSave: (List<String>) -> Unit) {
    var selected by remember { mutableStateOf(initial.toSet()) }
    var query by remember { mutableStateOf("") }
    val eligible = nodes.filter { it.tag != "direct" && it.type != "automatic" }
    val visible = eligible.filter { query.isBlank() || it.tag.contains(query.trim(), true) }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("$name · 候选池 ${selected.size}/32") }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("仅在所选节点之间自动切换。对地区或固定 IP 有要求时请缩小候选池，或直接选用固定节点。", style = MaterialTheme.typography.bodySmall)
            OutlinedTextField(query, { query = it }, label = { Text("搜索节点") }, modifier = Modifier.fillMaxWidth(), singleLine = true, enabled = !busy)
            LazyColumn(Modifier.heightIn(max = 330.dp)) {
                items(visible, key = { it.tag }) { node ->
                    val checked = node.tag in selected
                    Row(Modifier.fillMaxWidth().clickable(enabled = !busy) {
                        if (checked) selected = selected - node.tag else if (selected.size < 32) selected = selected + node.tag
                    }.padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked, onCheckedChange = null, enabled = !busy)
                        Text(node.tag, modifier = Modifier.weight(1f))
                    }
                }
            }
            val removed = selected - eligible.map { it.tag }.toSet()
            if (removed.isNotEmpty()) {
                Text("${removed.size} 个候选节点已不在订阅中，继续保留不会切换到其他节点。", style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { selected = selected - removed }, enabled = !busy) { Text("移除失效候选") }
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        }
    }, confirmButton = { TextButton(onClick = { onSave(selected.toList()) }, enabled = !busy && selected.isNotEmpty() && selected.size <= 32) { Text("使用此候选池") } },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("取消") } })
}
