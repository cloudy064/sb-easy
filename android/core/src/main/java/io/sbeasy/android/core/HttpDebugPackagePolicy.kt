package io.sbeasy.android.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

data class VerifiedPluginApk(val build: Long, val version: String, val signer: String, val sha256: String, val bytes: Long, val abis: Set<String>)

/** The Android UID sandbox plus an explicit manifest allowlist, applied to both local and catalog installs. */
object HttpDebugPackagePolicy {
    const val HOST_API = 2
    val CAPABILITIES = setOf("internet", "private-files", "tls-intercept")
    @Suppress("DEPRECATION")
    private fun flags(): Int = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_ACTIVITIES or
        PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or PackageManager.GET_META_DATA or
        if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES

    @Suppress("DEPRECATION")
    fun installed(context: Context): PackageInfo? = try { context.packageManager.getPackageInfo(HttpDebug.PACKAGE, flags()) }
    catch (_: PackageManager.NameNotFoundException) { null }

    fun requireInstalled(context: Context, hostVersion: String) {
        val info = requireNotNull(installed(context)) { "请先安装 HTTP(S) 调试插件" }
        require(info.applicationInfo?.uid != context.applicationInfo.uid) { "插件 UID 未隔离" }
        validate(context, info, hostVersion)
        PluginTrustStore.requireNotRevoked(versionCode(info))
    }

    @Suppress("DEPRECATION")
    fun inspect(context: Context, file: File, hostVersion: String, expected: PluginRelease? = null): VerifiedPluginApk {
        require(file.length() in 1..PluginCatalog.MAX_ARTIFACT) { "插件 APK 为空或超过 160 MiB" }
        // Bytes are verified before APK parsing on the downloaded/catalog path.
        val digest = digest(file)
        if (expected != null) require(file.length() == expected.bytes && digest == expected.sha256) { "插件文件与目录摘要或大小不符" }
        val info = requireNotNull(context.packageManager.getPackageArchiveInfo(file.path, flags())) { "不是有效的插件 APK" }
        val signer = validate(context, info, hostVersion)
        val build = versionCode(info)
        PluginTrustStore.requireNotRevoked(build)
        val abis = ZipFile(file).use { zip -> zip.entries().asSequence().map { it.name }.filter { it.startsWith("lib/") && it.endsWith(".so") }
            .map { it.split('/').getOrNull(1).orEmpty() }.toSet() }
        require(abis.isNotEmpty() && abis.any { it in Build.SUPPORTED_ABIS }) { "插件不支持本机 CPU 架构" }
        if (expected != null) {
            require(expected.id == "http-debug" && expected.platform == "android" && info.packageName == expected.packageName &&
                build == expected.build && info.versionName == expected.version && signer == expected.signerSha256 && abis == setOf(expected.abi)) {
                "APK 的实际包名、版本、架构或签名与目录不符"
            }
            require(expected.permissions.toSet() == CAPABILITIES) { "插件请求了宿主尚未支持的权限" }
            require(expected.compatible(hostVersion, requireNotNull(VpnRuntimeState.state.value.coreVersion) { "代理核心尚未初始化" }, HOST_API, Build.VERSION.SDK_INT, Build.SUPPORTED_ABIS.toList())) { "插件与应用或核心版本不兼容" }
        }
        return VerifiedPluginApk(build, info.versionName.orEmpty(), signer, digest, file.length(), abis)
    }

    @Suppress("DEPRECATION")
    private fun validate(context: Context, info: PackageInfo, hostVersion: String): String {
        require(info.packageName == HttpDebug.PACKAGE && versionCode(info) >= HttpDebug.MIN_PLUGIN_VERSION) { "请选择新版 sb-easy HTTP(S) 调试插件" }
        val app = requireNotNull(info.applicationInfo) { "插件缺少应用信息" }
        PluginWorkerBoundary.validate(info.sharedUserId, info.requestedPermissions.orEmpty().toSet(), info.activities?.size ?: 0,
            info.receivers?.size ?: 0, info.providers?.size ?: 0,
            info.services.orEmpty().map { PluginServiceBoundary(it.name, it.exported, it.permission) },
            app.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0, app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
            context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        val metadata = requireNotNull(app.metaData) { "插件缺少兼容性声明，请使用新版插件" }
        require(metadata.getInt("io.sbeasy.host_api") == HOST_API) { "插件控制协议与本应用不兼容" }
        require(PluginCatalog.inRange(hostVersion, metadata.getString("io.sbeasy.min_host").orEmpty(), metadata.getString("io.sbeasy.max_host").orEmpty()) &&
            PluginCatalog.inRange(requireNotNull(VpnRuntimeState.state.value.coreVersion) { "代理核心尚未初始化" },
                metadata.getString("io.sbeasy.min_core").orEmpty(), metadata.getString("io.sbeasy.max_core").orEmpty())) { "插件与应用或核心版本不兼容" }
        val signers = signers(info)
        val own = signers(context.packageManager.getPackageInfo(context.packageName, flags()))
        require(signers.size == 1 && signers == own) { "插件签名与主应用不匹配" }
        return signers.single()
    }

    @Suppress("DEPRECATION")
    fun versionCode(info: PackageInfo): Long = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
    @Suppress("DEPRECATION")
    private fun signers(info: PackageInfo): Set<String> = (if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures)
        .orEmpty().map { PluginCatalog.sha256(it.toByteArray()) }.toSet()
    fun digest(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input -> val buffer = ByteArray(65536); while (true) { val count = input.read(buffer); if (count < 0) break; digest.update(buffer, 0, count) } }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
