package io.sbeasy.android

import android.app.Activity
import android.app.ActivityOptions
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.os.Bundle
import io.sbeasy.android.core.*
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal object AppUpdateInstaller {
    private const val PREFS = "app_update_install"
    fun status(context: Context): String = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("status", "").orEmpty()
    fun stopped() = RuntimeBridge.control == null && VpnRuntimeState.state.value.phase in setOf(VpnPhase.DISCONNECTED, VpnPhase.ERROR)
    suspend fun install(context: Context, candidate: CachedApp) = AppUpdateStore.withVerifiedCached(candidate) { file ->
        require(stopped()) { "请先断开 VPN，再安装应用更新" }
        require(candidate.release.build >= AppPackagePolicy.currentBuild(context)) { "Android 不支持直接降级，请导出恢复包与加密偏好后手动卸载重装" }
        require(Build.VERSION.SDK_INT < 26 || context.packageManager.canRequestPackageInstalls()) { "请在系统设置允许此来源安装应用，再继续" }
        AppUpdateRescue.requireReady(context, candidate)
        withContext(Dispatchers.IO) {
            val installer = context.packageManager.packageInstaller
            installer.mySessions.filter { it.appPackageName == context.packageName }.forEach { installer.abandonSession(it.sessionId) }
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                setAppPackageName(context.packageName); setSize(file.length())
                if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
            }
            val sessionId = installer.createSession(params)
            val nonce = UUID.randomUUID().toString()
            val preferences = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            try {
                installer.openSession(sessionId).use { session ->
                    val digest = MessageDigest.getInstance("SHA-256")
                    session.openWrite("base.apk", 0, file.length()).use { output ->
                        file.inputStream().use { input ->
                            val buffer = ByteArray(65536)
                            while (true) { val count = input.read(buffer); if (count < 0) break; output.write(buffer, 0, count); digest.update(buffer, 0, count) }
                        }
                        session.fsync(output)
                    }
                    require(digest.digest().joinToString("") { "%02x".format(it) } == candidate.release.sha256) { "写入系统安装会话时 APK 内容发生变化" }
                    require(stopped()) { "VPN 已重新启动，请断开后重试" }
                    val callback = Intent(context, AppUpdateInstallResultActivity::class.java)
                        .setAction("io.sbeasy.android.APP_UPDATE_RESULT").setData(Uri.parse("sbeasy-update://result/$nonce"))
                    val flags = PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
                    val options = if (Build.VERSION.SDK_INT >= 35) ActivityOptions.makeBasic()
                        .setPendingIntentCreatorBackgroundActivityStartMode(ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED).toBundle() else null
                    val pending = PendingIntent.getActivity(context, sessionId, callback, flags, options)
                    check(preferences.edit().putInt("session", sessionId).putString("nonce", nonce).putLong("build", candidate.release.build)
                        .putString("status", "安装包已验证，等待系统安装确认。").commit()) { "无法保存安装会话记录" }
                    session.commit(pending.intentSender)
                }
            } catch (failure: Throwable) {
                runCatching { installer.abandonSession(sessionId) }
                preferences.edit().putString("status", "安装未完成：${failure.message.orEmpty()}").remove("nonce").apply()
                throw failure
            }
        }
    }

    @Suppress("DEPRECATION")
    fun handle(activity: Activity, intent: Intent) {
        val preferences = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val nonce = preferences.getString("nonce", null)
        val session = preferences.getInt("session", -1)
        if (nonce == null || intent.data?.lastPathSegment != nonce || intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -2) != session) return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            val build = preferences.getLong("build", -1)
            val snapshot = AppUpdateStore.state.value
            if (!stopped() || snapshot.error.isNotEmpty() || build in snapshot.revoked) {
                runCatching { activity.packageManager.packageInstaller.abandonSession(session) }
                preferences.edit().putString("status", "安装已取消：VPN 正在运行或应用版本的信任状态已变化。").remove("nonce").apply()
                return
            }
            val confirmation = if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java) else intent.getParcelableExtra(Intent.EXTRA_INTENT)
            runCatching { activity.startActivity(requireNotNull(confirmation) { "系统安装确认不可用" }) }.onFailure {
                runCatching { activity.packageManager.packageInstaller.abandonSession(session) }
                preferences.edit().putString("status", "无法打开系统安装确认：${it.message.orEmpty()}").remove("nonce").apply()
            }
        } else {
            val message = if (status == PackageInstaller.STATUS_SUCCESS) "系统报告安装成功；重新打开应用后检查版本。"
                else "系统未完成安装（状态 $status）：${intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty().take(500)}。已验证缓存保留。"
            preferences.edit().putString("status", message).remove("nonce").apply()
        }
    }
}

/** Explicit, non-exported target of the mutable system install result PendingIntent. */
class AppUpdateInstallResultActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); AppUpdateInstaller.handle(this, intent); finish() }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); AppUpdateInstaller.handle(this, intent); finish() }
}
