package io.sbeasy.android

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import io.sbeasy.android.core.*
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** No install is submitted until an external, readable rescue archive exists for these exact bytes. */
internal object AppUpdateRescue {
    private const val PREFS = "app_update_rescue"

    suspend fun export(context: Context, candidate: CachedApp, uri: Uri, passphrase: CharArray): AppInstallRecovery {
        requireExternal(context, uri)
        val payload = CoreGraph.repository.exportPreferences()
        val envelope = try { withContext(Dispatchers.Default) { PreferencesEnvelope.encrypt(payload, passphrase) } }
            finally { passphrase.fill('\u0000') }
        val proof = withContext(Dispatchers.IO) {
            requireNotNull(context.contentResolver.openOutputStream(uri, "wt")) { "无法创建应用外救援文件" }.use {
                AppUpdateStore.exportInstallRecovery(candidate, envelope, it)
            }.also { proof ->
                requireNotNull(context.contentResolver.openInputStream(uri)) { "救援包已写入但无法读回，请选择可读写的保存位置" }.use { AppRecoveryBundle.verify(it, proof.bundleSha256) }
            }
        }
        runCatching { context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION) }
        check(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("uri", uri.toString()).putString("bundle_sha256", proof.bundleSha256)
            .putLong("installed_build", proof.installedBuild).putString("installed_sha256", proof.installedSha256)
            .putLong("target_build", proof.targetBuild).putString("target_sha256", proof.targetSha256)
            .putLong("recovery_build", proof.recoveryBuild).putString("recovery_sha256", proof.recoverySha256)
            .putString("preferences_sha256", PluginCatalog.sha256(payload.toByteArray(Charsets.UTF_8))).commit()) { "无法保存救援验证记录，尚未允许安装" }
        return proof
    }

    suspend fun requireReady(context: Context, candidate: CachedApp) {
        val saved = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        require(saved.getLong("target_build", -1) == candidate.release.build && saved.getString("target_sha256", null) == candidate.release.sha256) { "请先为此更新导出并读回验证应用外救援包" }
        require(saved.getLong("installed_build", -1) == AppPackagePolicy.currentBuild(context)) { "安装版本已变化，请重新导出应用外救援包" }
        require(saved.getLong("recovery_build", -1) !in AppUpdateStore.state.value.revoked) { "救援版本已撤销，请重新导出安全的救援包" }
        val payload = CoreGraph.repository.exportPreferences()
        require(saved.getString("preferences_sha256", null) == PluginCatalog.sha256(payload.toByteArray(Charsets.UTF_8))) { "本机偏好已变化，请重新导出应用外救援包后安装" }
        withContext(Dispatchers.IO) {
            require(saved.getString("installed_sha256", null) == HttpDebugPackagePolicy.digest(File(context.applicationInfo.sourceDir))) { "当前 APK 已变化，请重新导出救援包" }
            val uri = Uri.parse(requireNotNull(saved.getString("uri", null)) { "缺少应用外救援文件" })
            requireExternal(context, uri)
            requireNotNull(context.contentResolver.openInputStream(uri)) { "无法读取应用外救援包，请重新保存后安装" }.use {
                AppRecoveryBundle.verify(it, requireNotNull(saved.getString("bundle_sha256", null)))
            }
        }
    }

    private fun requireExternal(context: Context, uri: Uri) {
        require(uri.scheme == "content" && uri.authority != "${context.packageName}.httpdebug.files" && DocumentsContract.isDocumentUri(context, uri)) { "请通过系统文件选择器保存到应用外的文档位置" }
        val id = DocumentsContract.getDocumentId(uri).replace('\\', '/')
        require(listOf("data", "obb", "media").none { id.contains("Android/$it/${context.packageName}", ignoreCase = true) }) { "不能把救援包保存在卸载时会删除的应用专属目录" }
    }
}
