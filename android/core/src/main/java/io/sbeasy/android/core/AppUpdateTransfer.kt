package io.sbeasy.android.core

import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

/** Release downloads may make one credential-free hop from GitHub to its official asset CDN. */
internal class AppUpdateTransfer(client: OkHttpClient = OkHttpClient.Builder().build()) {
    private val http = client.newBuilder().followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
        .connectTimeout(15, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS).callTimeout(15, TimeUnit.MINUTES).build()
    private val hints = http.newBuilder().callTimeout(20, TimeUnit.SECONDS).build()

    private fun get(rawUrl: String, client: OkHttpClient): Response {
        val request = Request.Builder().url(AppCatalog.https(rawUrl)).header("User-Agent", "sb-easy-android/updates").build()
        val response = client.newCall(request).execute()
        if (response.code !in setOf(301, 302, 303, 307, 308)) return response
        val target = response.use { GitHubAppUpdates.assetRedirect(request.url, requireNotNull(it.header("Location"))) }
        return client.newCall(Request.Builder().url(target).build()).execute()
    }
    private fun document(response: Response): String = response.use {
        require(it.isSuccessful) { "读取更新信息失败：HTTP ${it.code}" }
        val body = requireNotNull(it.body)
        require(body.contentLength() <= PluginCatalog.MAX_ENVELOPE) { "更新信息超过 1 MiB" }
        body.byteStream().use { input -> PreferencesEnvelope.utf8(AppRuntimeProvenance.readBounded(input, PluginCatalog.MAX_ENVELOPE)) }
    }
    fun catalog(rawUrl: String): String = document(get(rawUrl, hints))

    fun discover(server: String?, abis: List<String>): Pair<AndroidUpdateAsset, Boolean> {
        val deviceAbis = abis.filter { it in AppCatalog.ABIS }.distinct()
        require(deviceAbis.isNotEmpty()) { "本机 CPU 架构不受支持" }
        if (server != null) {
            val json = try {
                document(hints.newCall(GitHubAppUpdates.centerRequest(server, deviceAbis)).execute())
            } catch (_: Exception) { null }
            if (json != null) return GitHubAppUpdates.fromCenter(StrictJson.objectValue(json), deviceAbis) to true
        }
        val inventory = StrictJson.objectValue(catalog(GitHubAppUpdates.INVENTORY))
        return GitHubAppUpdates.fromInventory(inventory, deviceAbis) to false
    }
    suspend fun artifact(release: AppRelease, part: File, progress: (Long) -> Unit = {}) {
        require(release.bytes in 1..PluginCatalog.MAX_ARTIFACT)
        val url = AppCatalog.https(release.url)
        try {
            get(url, http).use { response ->
                require(response.isSuccessful) { "APK 下载失败：HTTP ${response.code}" }
                val body = requireNotNull(response.body)
                require(body.contentLength() == -1L || body.contentLength() == release.bytes) { "APK 下载长度与签名目录不符" }
                var size = 0L; val digest = MessageDigest.getInstance("SHA-256")
                body.byteStream().use { input -> part.outputStream().use { output ->
                    val buffer = ByteArray(65536)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val count = input.read(buffer); if (count < 0) break
                        size += count; require(size <= release.bytes) { "APK 下载超过签名大小" }
                        output.write(buffer, 0, count); digest.update(buffer, 0, count); progress(size)
                    }
                    output.fd.sync()
                } }
                require(size == release.bytes) { "APK 下载不完整" }
                require(digest.digest().joinToString("") { "%02x".format(it) } == release.sha256) { "APK 下载摘要与签名目录不符" }
            }
        } catch (error: Throwable) { part.delete(); throw error }
    }
}
