package io.sbeasy.android.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/** Filters are ORed; a domain includes subdomains, a host/IP is exact. */
data class CaptureConfig(
    val enabled: Boolean = false,
    val packages: List<String> = emptyList(),
    val domains: List<String> = emptyList(),
    val hosts: List<String> = emptyList(),
    val fileKB: Int = 512,
    val quotaMB: Int = 64,
    val rotateSeconds: Int = 60,
    val autoUpload: Boolean = false,
    val wifiOnly: Boolean = true,
    val uploadSeconds: Int = 60,
    val deleteAfterUpload: Boolean = false,
    val bpf: String = "",
) {
    fun validated(): CaptureConfig {
        require(fileKB in 128..768 && quotaMB in 8..256 && rotateSeconds in 10..600 && uploadSeconds in 30..3600) {
            "文件 128–768 KB；本地容量 8–256 MB；轮转 10–600 秒；上传间隔 30–3600 秒"
        }
        require(packages.size + domains.size + hosts.size <= 100) { "最多配置 100 条筛选条件" }
        require(packages.all { it.matches(Regex("[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z0-9_]+)+")) }) { "App 请填写完整包名" }
        fun normalize(value: String): String {
            require(value.isNotBlank() && !value.contains(Regex("[\\s/*?#@]"))) { "域名或 host 格式错误：$value" }
            val raw = value.trimEnd('.')
            val authority = if (raw.contains(':') && !raw.startsWith('[')) "[$raw]" else raw
            val url = "https://$authority/".toHttpUrlOrNull()
            require(url != null && url.port == 443) { "请填写域名或 IP，不要包含端口：$value" }
            return url.host
        }
        require(bpf.toByteArray(Charsets.UTF_8).size <= 4096 && !bpf.contains('\u0000')) { "BPF 表达式最长 4096 字节且不能包含空字符" }
        val result = copy(packages = packages.distinct(), domains = domains.map(::normalize).distinct(), hosts = hosts.map(::normalize).distinct(), bpf = bpf.trim())
        require(result.domains.none { it.contains(':') || it.matches(Regex("[0-9.]+")) }) { "IP 请填入精确 host/IP" }
        require(!enabled || result.packages.isNotEmpty() || result.domains.isNotEmpty() || result.hosts.isNotEmpty() || result.bpf.isNotEmpty()) { "开启采集前至少设置一个筛选条件" }
        return result
    }
    fun json(): JSONObject = JSONObject().put("enabled", enabled)
        .put("packages", JSONArray(packages)).put("domains", JSONArray(domains)).put("hosts", JSONArray(hosts))
        .put("file_kb", fileKB).put("quota_mb", quotaMB).put("rotate_seconds", rotateSeconds)
        .put("auto_upload", autoUpload).put("wifi_only", wifiOnly).put("upload_seconds", uploadSeconds)
        .put("delete_after_upload", deleteAfterUpload)
        .put("bpf", bpf)
    companion object {
        fun parse(raw: String): CaptureConfig {
            val j = JSONObject(raw)
            fun strings(key: String): List<String> = j.optJSONArray(key)?.let { a -> (0 until a.length()).map { a.getString(it) } }.orEmpty()
            return CaptureConfig(j.optBoolean("enabled"), strings("packages"), strings("domains"), strings("hosts"),
                j.optInt("file_kb", 512), j.optInt("quota_mb", 64), j.optInt("rotate_seconds", 60),
                j.optBoolean("auto_upload"), j.optBoolean("wifi_only", true), j.optInt("upload_seconds", 60),
                j.optBoolean("delete_after_upload"), j.optString("bpf")).validated()
        }
    }
}

data class CaptureFile(val file: File, val uploaded: Boolean)

object PacketCapture {
    private lateinit var context: Context
    private val uploadMutex = Mutex()
    @Volatile private var lastAttempt = 0L
    @Volatile var uploadStatus: String = "尚未上传"
        private set
    @Volatile var runtimeError: String = ""
    @Volatile var nativeStatus: () -> String = { "{}" }
    @Volatile var rotate: () -> Unit = {}
    @Volatile var validateFilter: (String) -> Unit = { expression ->
        check(expression.isBlank()) { "BPF 引擎尚未初始化" }
    }
    fun initialize(context: Context) { this.context = context.applicationContext }
    private fun preferences() = context.getSharedPreferences("packet_capture", Context.MODE_PRIVATE)
    fun config(): CaptureConfig = runCatching { CaptureConfig.parse(preferences().getString("config", "{}")!!) }.getOrDefault(CaptureConfig())
    fun save(config: CaptureConfig) { check(preferences().edit().putString("config", config.validated().json().toString()).commit()) { "采集配置保存失败" }; lastAttempt = 0 }
    fun directory(enrollment: Enrollment): File {
        val key = sha256((enrollment.server + "\n" + enrollment.hostId).toByteArray()).take(32)
        return File(context.filesDir, "captures/$key").apply { mkdirs() }
    }
    fun nativeConfig(enrollment: Enrollment): String = config().json().put("directory", directory(enrollment).absolutePath).toString()
    fun files(enrollment: Enrollment): List<CaptureFile> = directory(enrollment).listFiles().orEmpty()
        .filter { it.extension == "pcap" }.sortedByDescending { it.name }.map { CaptureFile(it, marker(it).exists()) }
    private fun marker(file: File) = File(file.parentFile, file.name + ".uploaded")
    suspend fun delete(file: CaptureFile) = uploadMutex.withLock { withContext(Dispatchers.IO) {
        check(file.file.delete() || !file.file.exists()) { "删除失败" }; marker(file.file).delete()
    } }
    suspend fun upload(enrollment: Enrollment, client: ControlPlaneClient, manual: Boolean = false) = uploadMutex.withLock {
        withContext(Dispatchers.IO) {
            val cfg = config()
            if (!manual && (!cfg.autoUpload || System.currentTimeMillis() - lastAttempt < cfg.uploadSeconds * 1000L)) return@withContext
            if (cfg.wifiOnly) {
                val cm = context.getSystemService(ConnectivityManager::class.java)
                val wifi = cm.allNetworks.any { n -> cm.getNetworkCapabilities(n)?.let {
                    it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                } == true }
                if (!wifi) { uploadStatus = "等待 Wi-Fi"; return@withContext }
            }
            lastAttempt = System.currentTimeMillis()
            rotate()
            try {
                var uploaded = 0
                // Keep background batches bounded; an explicit upload drains the pending queue.
                for (entry in files(enrollment).filterNot { it.uploaded }.sortedBy { it.file.name }.take(if (manual) Int.MAX_VALUE else 8)) {
                    currentCoroutineContext().ensureActive()
                    val data = entry.file.readBytes()
                    val digest = sha256(data)
                    client.uploadCapture(enrollment, digest, data, cfg.wifiOnly)
                    marker(entry.file).writeText(digest)
                    if (cfg.deleteAfterUpload) { if (entry.file.delete()) marker(entry.file).delete() }
                    uploaded++
                }
                uploadStatus = "本轮上传 $uploaded 个文件；待上传 ${files(enrollment).count { !it.uploaded }} 个"
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                uploadStatus = "上传失败，文件已保留：${error.message}"
                if (manual) throw error
            }
        }
    }
    internal fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
