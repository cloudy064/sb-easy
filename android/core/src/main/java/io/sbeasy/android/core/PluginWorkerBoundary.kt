package io.sbeasy.android.core

data class PluginServiceBoundary(val name: String, val exported: Boolean, val permission: String?)

/** Actual PackageManager fields feed this policy; a catalog cannot grant extra Android capabilities. */
object PluginWorkerBoundary {
    fun validate(sharedUid: String?, permissions: Set<String>, activityCount: Int, receiverCount: Int, providerCount: Int,
                 services: List<PluginServiceBoundary>, allowBackup: Boolean, debuggable: Boolean, hostDebuggable: Boolean) {
        require(sharedUid == null) { "插件不能与其他应用共享 UID" }
        require(permissions == setOf("android.permission.INTERNET")) { "插件超出受支持权限范围" }
        require(activityCount == 0 && receiverCount == 0 && providerCount == 0) { "插件含未授权的活动、广播或数据提供者" }
        val service = services.singleOrNull()
        require(service != null && service.name == "io.sbeasy.httpdebug.EngineService" && service.exported &&
            service.permission == "io.sbeasy.android.permission.HTTP_DEBUG") { "插件控制服务不符合签名权限边界" }
        require(!allowBackup) { "插件不能启用系统备份" }
        require(!debuggable || hostDebuggable) { "正式应用不能加载可调试插件" }
    }
}
