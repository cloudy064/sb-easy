package io.sbeasy.android

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
import io.sbeasy.android.core.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun PreferencesScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val repo = CoreGraph.repository
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var encrypted by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<String?>(null) }
    var preview by remember { mutableStateOf<PreferencesPreview?>(null) }
    var server by remember { mutableStateOf(repo.state.value.enrollment?.server.orEmpty()) }
    var username by remember { mutableStateOf("") }
    var accountPassword by remember { mutableStateOf("") }
    var mfa by remember { mutableStateOf("") }
    var needsMfa by remember { mutableStateOf(false) }
    var session by remember { mutableStateOf<PreferencesSyncClient?>(null) }
    var loggedIn by remember { mutableStateOf(false) }
    var slot by remember { mutableStateOf("android-personal") }
    var remote by remember { mutableStateOf<RemotePreferences?>(null) }
    var upload by remember { mutableStateOf<Pair<Long, String>?>(null) }
    var deleteRevision by remember { mutableStateOf<Long?>(null) }
    DisposableEffect(session) { val current = session; onDispose { current?.close() } }
    BackHandler(enabled = !busy, onBack = onBack)

    fun perform(action: suspend () -> Unit) {
        busy = true; message = ""
        scope.launch {
            try { action() }
            catch (error: Exception) {
                preview = null; upload = null; deleteRevision = null
                message = error.message ?: "操作失败，原配置保留"
            }
            finally { busy = false; loggedIn = session?.authenticated == true }
        }
    }
    suspend fun encrypt(): String {
        val secret = password.toCharArray(); password = ""
        try {
            val payload = repo.exportPreferences()
            return withContext(Dispatchers.Default) { PreferencesEnvelope.encrypt(payload, secret) }
        } finally { secret.fill('\u0000') }
    }
    suspend fun prepareImport(envelope: String) {
        val secret = password.toCharArray(); password = ""
        try {
            val payload = withContext(Dispatchers.Default) { PreferencesEnvelope.decrypt(envelope, secret) }
            preview = repo.previewPreferences(payload)
        } finally { secret.fill('\u0000') }
    }
    val exportFile = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val data = pendingExport; pendingExport = null
        if (uri != null && data != null) perform {
            withContext(Dispatchers.IO) {
                requireNotNull(context.contentResolver.openOutputStream(uri, "wt")) { "无法写入所选文件" }.use { it.write(data.toByteArray(Charsets.UTF_8)) }
            }
            message = "加密偏好已导出；请保管恢复口令，中心无法重置它。"
        }
    }
    val importFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) perform {
            encrypted = withContext(Dispatchers.IO) {
                val bytes = requireNotNull(context.contentResolver.openInputStream(uri)) { "无法读取所选文件" }.use { input ->
                    val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        require(output.size() + count <= PreferencesEnvelope.MAX_BYTES) { "偏好文件超过 1 MiB" }
                        output.write(buffer, 0, count)
                    }
                    output.toByteArray()
                }
                PreferencesEnvelope.utf8(bytes).also(PreferencesEnvelope::inspect)
            }
            message = "文件已读取，请填写恢复口令并预览。"
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        TextButton(onClick = onBack, enabled = !busy) { Text("返回设置") }
        Text("加密偏好与中心漫游", style = MaterialTheme.typography.headlineSmall)
        Text("保存订阅、缓存节点及一般域名/出口/健康偏好。设备凭据、应用包规则、WireGuard 密钥、采集授权和 CA 不会导出。导入前请停止 VPN。")
        OutlinedTextField(password, { password = it }, enabled = !busy, label = { Text("恢复口令（至少 12 个 UTF-8 字节）") },
            visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password), modifier = Modifier.fillMaxWidth())
        Text("此口令只用于本机加密，不发送给中心、不保存。忘记口令无法恢复。文件上限 1 MiB，目前只支持 Android 偏好内容。", style = MaterialTheme.typography.bodySmall)
        Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("本地文件", style = MaterialTheme.typography.titleMedium)
            Button(enabled = !busy && password.isNotEmpty(), onClick = { perform {
                pendingExport = encrypt(); exportFile.launch("sb-easy-android-preferences.sbp")
            } }) { Text("加密并导出") }
            OutlinedButton(enabled = !busy, onClick = { encrypted = null; importFile.launch(arrayOf("*/*")) }) { Text("选择加密文件") }
            OutlinedButton(enabled = !busy && encrypted != null && password.isNotEmpty(), onClick = { perform { prepareImport(requireNotNull(encrypted)) } }) { Text("解密并预览导入") }
        } }
        Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("中心账户漫游", style = MaterialTheme.typography.titleMedium)
            Text("单独登录中心账户；会话只保留到离开本页。只有点击同步才传输加密文件，独立模式的设备状态不会随之上传。", style = MaterialTheme.typography.bodySmall)
            if (!loggedIn) {
                if (!needsMfa) {
                    OutlinedTextField(server, { server = it }, enabled = !busy, label = { Text("HTTPS 中心地址") }, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(username, { username = it }, enabled = !busy, label = { Text("中心账户") }, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(accountPassword, { accountPassword = it }, enabled = !busy, label = { Text("中心登录密码") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
                    Button(enabled = !busy, onClick = { perform {
                        val next = PreferencesSyncClient(server); session = next; remote = null
                        val secret = accountPassword; accountPassword = ""
                        needsMfa = withContext(Dispatchers.IO) { next.login(username, secret) }
                        if (!needsMfa) remote = withContext(Dispatchers.IO) { next.get(slot) }
                        message = if (needsMfa) "请输入动态码或恢复码完成 MFA。" else "已登录，已读取云端版本。"
                    } }) { Text("登录中心账户") }
                } else {
                    OutlinedTextField(mfa, { mfa = it }, enabled = !busy, label = { Text("动态码或恢复码") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
                    Button(enabled = !busy, onClick = { perform {
                        val current = requireNotNull(session); val code = mfa; mfa = ""
                        withContext(Dispatchers.IO) { current.completeMfa(code) }
                        needsMfa = false; remote = withContext(Dispatchers.IO) { current.get(slot) }; message = "MFA 验证完成，已读取云端版本。"
                    } }) { Text("完成 MFA") }
                    TextButton(enabled = !busy, onClick = { session = null; needsMfa = false; mfa = "" }) { Text("重新登录") }
                }
            } else {
                OutlinedTextField(slot, { slot = it; remote = null }, enabled = !busy, label = { Text("私有槽位") }, modifier = Modifier.fillMaxWidth())
                Text(remote?.let { "云端版本 ${it.revision}" + if (it.envelope == null) " · 无已保存偏好" else " · 有加密偏好" } ?: "请先读取此槽位的版本")
                OutlinedButton(enabled = !busy, onClick = { perform {
                    remote = withContext(Dispatchers.IO) { requireNotNull(session).get(slot) }; message = "已读取最新云端版本；本机偏好未改动。"
                } }) { Text("重新读取云端") }
                OutlinedButton(enabled = !busy && remote?.envelope != null && password.isNotEmpty(), onClick = { perform { prepareImport(requireNotNull(remote?.envelope)) } }) { Text("解密云端并预览导入") }
                Button(enabled = !busy && remote != null && password.isNotEmpty(), onClick = { perform {
                    upload = requireNotNull(remote).revision to encrypt()
                } }) { Text("加密本机并同步到中心") }
                TextButton(enabled = !busy && remote?.envelope != null, onClick = { deleteRevision = remote?.revision }) { Text("删除云端偏好") }
                TextButton(enabled = !busy, onClick = { perform {
                    try { withContext(Dispatchers.IO) { session?.logout() } }
                    finally { session = null; loggedIn = false; remote = null; needsMfa = false }
                } }) { Text("退出漫游账户") }
            }
        } }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (message.isNotBlank()) Text(message)
    }
    preview?.let { candidate -> AlertDialog(onDismissRequest = { if (!busy) preview = null }, title = { Text("确认导入偏好") },
        text = { Text(candidate.description) }, confirmButton = { TextButton(enabled = !busy, onClick = { perform {
            repo.importPreferences(candidate); preview = null; encrypted = null; SubscriptionRefreshService.schedule(context)
            message = "已导入偏好，可在代理和订阅页检查后连接。"
        } }) { Text("确认替换一般偏好") } }, dismissButton = { TextButton(enabled = !busy, onClick = { preview = null }) { Text("取消") } }) }
    upload?.let { candidate -> AlertDialog(onDismissRequest = { if (!busy) upload = null }, title = { Text("确认同步到中心") },
        text = { Text("将用本机加密偏好替换槽位 $slot 的版本 ${candidate.first}。其他设备已更新时会拒绝覆盖。恢复口令不会上传。") },
        confirmButton = { TextButton(enabled = !busy, onClick = { perform {
            remote = withContext(Dispatchers.IO) { requireNotNull(session).put(slot, candidate.first, candidate.second) }
            upload = null; message = "加密偏好已同步到中心。"
        } }) { Text("确认同步") } }, dismissButton = { TextButton(enabled = !busy, onClick = { upload = null }) { Text("取消") } }) }
    deleteRevision?.let { revision -> AlertDialog(onDismissRequest = { if (!busy) deleteRevision = null }, title = { Text("删除云端偏好") },
        text = { Text("删除槽位 $slot 的加密内容，保留递增版本以防旧设备重新覆盖。不会删除本机偏好。") },
        confirmButton = { TextButton(enabled = !busy, onClick = { perform {
            remote = withContext(Dispatchers.IO) { requireNotNull(session).delete(slot, revision) }; deleteRevision = null; message = "云端偏好已删除。"
        } }) { Text("确认删除") } }, dismissButton = { TextButton(enabled = !busy, onClick = { deleteRevision = null }) { Text("取消") } }) }
}
