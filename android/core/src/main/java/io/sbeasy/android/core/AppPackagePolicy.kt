package io.sbeasy.android.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

/** Pure boundary shared by the Android package parser and JVM negative tests. */
data class AppArtifactIdentity(val packageName: String, val version: String, val build: Long, val minOs: Int,
    val signers: List<String>, val abis: Set<String>, val debuggable: Boolean)
object AppPackagePolicy {
    @Suppress("DEPRECATION")
    private fun flags() = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
    @Suppress("DEPRECATION")
    fun currentSigner(context: Context): String {
        val info = context.packageManager.getPackageInfo(context.packageName, flags())
        val certificates = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
        require(certificates?.size == 1) { "当前应用必须只有一个签名证书" }
        return PluginCatalog.sha256(requireNotNull(certificates).single().toByteArray())
    }
    @Suppress("DEPRECATION")
    fun currentBuild(context: Context): Long = HttpDebugPackagePolicy.versionCode(context.packageManager.getPackageInfo(context.packageName, 0))
    fun compatible(context: Context, release: AppRelease): Boolean = release.minOs <= Build.VERSION.SDK_INT &&
        release.packageName == context.packageName && release.abis.any { it in Build.SUPPORTED_ABIS } &&
        runCatching { release.signer == currentSigner(context) }.getOrDefault(false)

    fun validateIdentity(actual: AppArtifactIdentity, expected: AppRelease, ownSigner: String, os: Int, deviceAbis: List<String>, ownDebuggable: Boolean) {
        require(actual.packageName == expected.packageName && actual.packageName == "io.sbeasy.android" && actual.version == expected.version &&
            actual.build == expected.build && actual.minOs == expected.minOs) { "APK 的实际包名、版本或最低系统版本与签名目录不符" }
        require(actual.signers.size == 1 && actual.signers.single() == ownSigner && ownSigner == expected.signer) { "APK 签名与当前应用的单一签名证书不一致" }
        require(actual.abis == expected.abis && actual.abis.any { it in deviceAbis } && actual.minOs <= os) { "APK 实际架构或系统版本不兼容" }
        require(!actual.debuggable || ownDebuggable) { "正式应用不能安装调试构建" }
    }

    @Suppress("DEPRECATION")
    fun inspect(context: Context, file: File, release: AppRelease) {
        require(file.length() == release.bytes && file.length() in 1..PluginCatalog.MAX_ARTIFACT && HttpDebugPackagePolicy.digest(file) == release.sha256) { "APK 大小或 SHA-256 与签名目录不符" }
        val info = requireNotNull(context.packageManager.getPackageArchiveInfo(file.path, flags())) { "APK 无法解析" }
        val app = requireNotNull(info.applicationInfo)
        require(info.sharedUserId == null) { "不允许使用共享 UID 的主应用更新" }
        val certificates = if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures
        val abis = AppRuntimeProvenance.verify(file, release)
        val actual = AppArtifactIdentity(info.packageName, info.versionName.orEmpty(), HttpDebugPackagePolicy.versionCode(info), app.minSdkVersion,
            certificates.orEmpty().map { PluginCatalog.sha256(it.toByteArray()) }, abis, app.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        validateIdentity(actual, release, currentSigner(context), Build.VERSION.SDK_INT, Build.SUPPORTED_ABIS.toList(), context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
    }
}

object AppRuntimeProvenance {
    fun verify(apk: File, release: AppRelease): Set<String> = ZipFile(apk).use { zip ->
        val entries = zip.entries().asSequence().toList()
        require(entries.size <= 20000 && entries.map { it.name }.distinct().size == entries.size) { "APK ZIP 含重复条目或过多文件" }
        val asset = requireNotNull(zip.getEntry("assets/libbox-provenance.json")) { "APK 缺少内核构建来源记录" }
        require(asset.size in 1..65536) { "内核来源记录大小无效" }
        val raw = zip.getInputStream(asset).use { input -> readBounded(input, 65536) }
        require(PluginCatalog.sha256(raw) == release.provenanceSha256) { "内核来源记录与签名目录不符" }
        val root = StrictJson.objectValue(PreferencesEnvelope.utf8(raw))
        AppCatalog.fields(root, setOf("format", "version", "source_kind", "core_version", "source_revision", "overlay_sha256", "source_changes_sha256", "toolchain", "aar_sha256", "native_sha256"))
        require(root.opt("format") == "sb-easy.libbox-provenance" && AppCatalog.integer(root, "version", 1, 1) == 1L &&
            root.opt("source_kind") == "local-pinned-build" && root.opt("core_version") == release.coreVersion && root.opt("source_revision") == release.sourceRevision) { "APK 内核版本或源码 revision 与签名目录不符" }
        for (name in listOf("aar_sha256", "overlay_sha256", "source_changes_sha256")) AppCatalog.digest(root, name)
        val toolchain = root.getJSONObject("toolchain"); AppCatalog.fields(toolchain, setOf("go", "gomobile", "ndk"))
        for (name in listOf("go", "gomobile", "ndk")) require(AppCatalog.string(toolchain, name).length in 1..256) { "内核工具链声明无效" }
        val native = root.getJSONObject("native_sha256")
        require(native.keys().asSequence().toSet() == AppCatalog.ABIS) { "内核来源记录缺少架构" }
        AppCatalog.ABIS.forEach { AppCatalog.digest(native, it) }
        val libraries = entries.filter { it.name.startsWith("lib/") && it.name.endsWith(".so") }
        val abis = libraries.map { it.name.split('/').getOrNull(1).orEmpty() }.toSet()
        require(abis == release.abis) { "APK 内原生库架构与签名目录不符" }
        abis.forEach { abi ->
            val library = requireNotNull(zip.getEntry("lib/$abi/libbox.so")) { "APK 缺少 $abi 内核" }
            require(library.size in 1..192L * 1024 * 1024) { "内核原生库大小无效" }
            val actual = zip.getInputStream(library).use { input -> digestBounded(input, 192L * 1024 * 1024) }
            require(actual == native.getString(abi)) { "$abi 内核原生库与构建来源记录不符" }
        }
        abis
    }
    fun readBounded(input: InputStream, limit: Int): ByteArray {
        val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(8192)
        while (true) { val count = input.read(buffer); if (count < 0) break; require(output.size() + count <= limit) { "文件超过读取上限" }; output.write(buffer, 0, count) }
        return output.toByteArray()
    }
    private fun digestBounded(input: InputStream, limit: Long): String {
        val digest = MessageDigest.getInstance("SHA-256"); val buffer = ByteArray(65536); var size = 0L
        while (true) { val count = input.read(buffer); if (count < 0) break; size += count; require(size <= limit) { "解压后的内核超过上限" }; digest.update(buffer, 0, count) }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
