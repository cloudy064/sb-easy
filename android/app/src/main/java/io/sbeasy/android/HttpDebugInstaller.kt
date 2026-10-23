package io.sbeasy.android

import android.content.Context
import android.net.Uri
import io.sbeasy.android.core.HttpDebugPackagePolicy
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal object HttpDebugInstaller {
    @Suppress("DEPRECATION")
    suspend fun stage(context: Context, uri: Uri): File = withContext(Dispatchers.IO) {
        val folder = File(context.cacheDir, "http-debug-install").apply { mkdirs() }
        val target = File(folder, "verified-plugin.apk")
        try {
            var size = 0L
            requireNotNull(context.contentResolver.openInputStream(uri)) { "无法读取插件文件" }.use { input ->
                target.outputStream().use { output ->
                    val buffer = ByteArray(65536)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        size += count
                        require(size <= 160L * 1024 * 1024) { "插件 APK 超过 160 MB" }
                        output.write(buffer, 0, count)
                    }
                }
            }
            HttpDebugPackagePolicy.inspect(context, target, BuildConfig.VERSION_NAME)
            target
        } catch (error: Throwable) { target.delete(); throw error }
    }
}
