package io.sbeasy.android

import android.content.pm.ApplicationInfo
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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class InstalledApplication(val packageName: String, val label: String, val system: Boolean)

@Composable
internal fun ApplicationPicker(initial: List<String>, onDismiss: () -> Unit, onSelect: (List<String>) -> Unit) {
    val context = LocalContext.current
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf(initial.toSet()) }
    val applications by produceState<List<InstalledApplication>?>(null) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                context.packageManager.getInstalledApplications(0).map { app ->
                    InstalledApplication(app.packageName, context.packageManager.getApplicationLabel(app).toString(),
                        app.flags and ApplicationInfo.FLAG_SYSTEM != 0)
                }.sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
            }.getOrDefault(emptyList())
        }
    }
    val visible = applications.orEmpty().filter { app ->
        (showSystem || !app.system || app.packageName in selected) &&
            (query.isBlank() || app.label.contains(query.trim(), true) || app.packageName.contains(query.trim(), true))
    }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("选择应用（已选 ${selected.size}）") }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(query, { query = it }, label = { Text("搜索应用名称或包名") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("显示系统应用", modifier = Modifier.weight(1f))
                Switch(showSystem, { showSystem = it })
            }
            Text("选择后，该应用的目标连接和 DNS 跟随本组出口。中心地址与受管 WireGuard 网络优先。", style = MaterialTheme.typography.bodySmall)
            if (applications == null) CircularProgressIndicator()
            LazyColumn(Modifier.heightIn(max = 350.dp)) {
                items(visible, key = { it.packageName }) { app ->
                    val checked = app.packageName in selected
                    Row(Modifier.fillMaxWidth().clickable {
                        if (checked) selected = selected - app.packageName else if (selected.size < 128) selected = selected + app.packageName
                    }.padding(vertical = 5.dp), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked, onCheckedChange = null)
                        Column(Modifier.weight(1f)) {
                            Text(app.label)
                            Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
                if (applications != null && visible.isEmpty()) item { Text("没有匹配的已安装应用；也可在分组中手动填写包名。") }
            }
            val absent = selected - applications.orEmpty().map { it.packageName }.toSet()
            if (absent.isNotEmpty()) Text("另外保留 ${absent.size} 个当前未安装的包名。", style = MaterialTheme.typography.bodySmall)
        }
    }, confirmButton = { TextButton(onClick = { onSelect(selected.toList().sorted()) }) { Text("使用所选应用") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } })
}
