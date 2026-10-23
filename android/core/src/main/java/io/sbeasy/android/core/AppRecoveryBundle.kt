package io.sbeasy.android.core

import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

data class AppInstallRecovery(val installedBuild: Long, val installedSha256: String, val targetBuild: Long,
    val targetSha256: String, val recoveryBuild: Long, val recoverySha256: String, val bundleSha256: String)

/** A complete rescue archive can be opened without a working sb-easy process. */
object AppRecoveryBundle {
    const val MAX_BYTES = PluginCatalog.MAX_ARTIFACT + PluginCatalog.MAX_ENVELOPE + PreferencesEnvelope.MAX_BYTES + 65536L

    fun write(apk: File, release: AppRelease, signedReceipt: String, encryptedPreferences: String,
              installedBuild: Long, targetBuild: Long, output: OutputStream): String {
        require(apk.length() == release.bytes && HttpDebugPackagePolicy.digest(apk) == release.sha256) { "恢复 APK 已变化，请重新下载验证" }
        require(signedReceipt.toByteArray(Charsets.UTF_8).size <= PluginCatalog.MAX_ENVELOPE)
        PreferencesEnvelope.inspect(encryptedPreferences)
        val digest = MessageDigest.getInstance("SHA-256")
        ZipOutputStream(DigestOutputStream(output, digest)).use { zip ->
            zip.putNextEntry(ZipEntry("sb-easy-${release.version}-${release.build}.apk"))
            apk.inputStream().use { it.copyTo(zip) }; zip.closeEntry()
            for ((name, text) in listOf(
                "signed-catalog.json" to signedReceipt,
                "preferences.sbp" to encryptedPreferences,
                "RECOVERY.txt" to instructions(release, installedBuild, targetBuild),
            )) {
                zip.putNextEntry(ZipEntry(name)); zip.write(text.toByteArray(Charsets.UTF_8)); zip.closeEntry()
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    fun verify(input: InputStream, expectedSha256: String) {
        val digest = MessageDigest.getInstance("SHA-256"); val buffer = ByteArray(65536); var size = 0L
        while (true) {
            val count = input.read(buffer); if (count < 0) break
            size += count; require(size <= MAX_BYTES) { "应用外救援包超过大小上限" }; digest.update(buffer, 0, count)
        }
        require(size > 0 && digest.digest().joinToString("") { "%02x".format(it) } == expectedSha256) { "应用外救援包无法完整读回或内容已变化，尚未允许安装" }
    }

    private fun instructions(release: AppRelease, installedBuild: Long, targetBuild: Long) = """
sb-easy Android 应用外救援 / Recovery without opening sb-easy

更新前版本码 / Installed before update: $installedBuild
计划安装版本码 / Update target: $targetBuild
此包内 APK / Included APK: ${release.version} (${release.build})
APK SHA-256: ${release.sha256}
Certificate SHA-256: ${release.signer}

如果新版无法启动，请使用系统文件管理器解压本 ZIP；无需打开 sb-easy。
普通 Android 应用无法直接降低版本码。要安装较低版本，请手动卸载现有应用，
再从解压后的 APK 安装，打开“设置 → 加密偏好备份与中心漫游”，选择 preferences.sbp，
使用导出时的恢复口令解密并预览导入。受管设备需要重新注册。
卸载会删除设备令牌、WireGuard 密钥、应用私有文件与更新信任状态；这些不在偏好备份中。
系统已安装的用户 CA 不会因卸载自动移除，请在系统安全设置中手动检查和移除调试 CA。
重装后读取最新可信签名目录，恢复最新撤销信息。此过程不是无损、静默或原子回滚。
${if (release.build >= targetBuild && targetBuild > installedBuild) "原安装版已撤销或没有合格的旧版：此包只能重新安装目标版本，不能承诺恢复到旧版。" else "此 APK 是导出时已验证、未被已知目录撤销的恢复版本。"}

If the new app cannot start, extract this ZIP with the system file manager.
Android blocks ordinary versionCode downgrades. Manually uninstall the current
app if needed, install the included APK, then import preferences.sbp through
Settings using your recovery passphrase. Enrollment/device secrets are excluded;
managed devices must enroll again. Uninstall clears private data and local trust
state. Remove exported debug CAs in system settings and fetch a fresh catalog.
This is not an atomic or lossless rollback. Keep the passphrase separately.
""".trimIndent() + "\n"
}
