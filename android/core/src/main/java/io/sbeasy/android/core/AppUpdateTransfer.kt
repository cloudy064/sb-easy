package io.sbeasy.android.core

import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okhttp3.OkHttpClient
import okhttp3.Request

/** All requests use a bounded HTTPS transfer; redirects never change the signed destination. */
internal class AppUpdateTransfer(client: OkHttpClient = OkHttpClient.Builder().build()) {
    private val http = client.newBuilder().followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
        .connectTimeout(15, TimeUnit.SECONDS).readTimeout(20, TimeUnit.SECONDS).callTimeout(180, TimeUnit.SECONDS).build()
    fun catalog(rawUrl: String): String {
        val url = AppCatalog.https(rawUrl)
        return http.newCall(Request.Builder().url(url).header("User-Agent", "sb-easy-android/updates").build()).execute().use { response ->
            require(response.isSuccessful) { "读取应用目录失败：HTTP ${response.code}" }
            val body = requireNotNull(response.body); require(body.contentLength() <= PluginCatalog.MAX_ENVELOPE) { "应用目录超过 1 MiB" }
            body.byteStream().use { PreferencesEnvelope.utf8(AppRuntimeProvenance.readBounded(it, PluginCatalog.MAX_ENVELOPE)) }
        }
    }
    suspend fun artifact(release: AppRelease, part: File, progress: (Long) -> Unit = {}) {
        require(release.bytes in 1..PluginCatalog.MAX_ARTIFACT)
        val url = AppCatalog.https(release.url)
        try {
            http.newCall(Request.Builder().url(url).header("User-Agent", "sb-easy-android/updates").build()).execute().use { response ->
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
