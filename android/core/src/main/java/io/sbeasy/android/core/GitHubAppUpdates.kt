package io.sbeasy.android.core

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Request
import org.json.JSONObject

internal data class AndroidUpdateAsset(val tag: String, val abi: String) {
    private val base = "https://github.com/cloudy064/sb-easy/releases/download/$tag/"
    val catalogUrl = base + "sb-easy-android-catalog.json"
    val apkUrl = base + "sb-easy-android-${tag.removePrefix("android-")}-$abi.apk"
}

internal object GitHubAppUpdates {
    const val INVENTORY = "https://raw.githubusercontent.com/cloudy064/sb-easy/master/config/client-releases.json"
    private val stableTag = Regex("android-v(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})\\.(0|[1-9][0-9]{0,5})")
    private val assetPath = Regex("/cloudy064/sb-easy/releases/download/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")

    /* A legacy HTTP center can supply this public hint. Only ABI names leave the device.
     * Both returned URLs must independently match this repository before HTTPS verification. */
    fun centerRequest(server: String, abis: List<String>): Request {
        val base = server.toHttpUrl()
        require(java.net.URI(server).rawUserInfo == null && base.query == null && base.fragment == null)
        val url = base.newBuilder().apply {
            if (base.encodedPath.endsWith("/")) removePathSegment(base.pathSize - 1)
            addPathSegments("api/agent/android-update")
            addPathSegment(abis.joinToString(","))
        }.build()
        return Request.Builder().url(url).get().build()
    }

    private fun asset(tag: String, abi: String, deviceAbis: List<String>): AndroidUpdateAsset {
        require(stableTag.matches(tag)) { "没有可用的 Android 稳定版签名目录" }
        require(abi == "universal" || (abi in AppCatalog.ABIS && abi in deviceAbis)) { "更新包架构与本机不符" }
        return AndroidUpdateAsset(tag, abi)
    }

    fun fromCenter(json: JSONObject, deviceAbis: List<String>): AndroidUpdateAsset {
        val offer = asset(json.getString("tag"), json.getString("abi"), deviceAbis)
        require(json.getString("catalog_url") == offer.catalogUrl && json.getString("apk_url") == offer.apkUrl) {
            "中心返回的更新地址与官方 GitHub Release 不一致"
        }
        return offer
    }

    fun fromInventory(json: JSONObject, deviceAbis: List<String>): AndroidUpdateAsset {
        val release = json.getJSONObject("published").getJSONObject("android")
        val rows = release.getJSONArray("artifacts")
        for (abi in deviceAbis.filter { it in AppCatalog.ABIS } + "universal") {
            val offer = asset(release.getString("tag"), abi, deviceAbis)
            if ((0 until rows.length()).any { rows.getJSONObject(it).optString("url") == offer.apkUrl }) return offer
        }
        error("GitHub Release 没有适合本机的 APK")
    }

    /* GitHub serves release bytes from a temporary HTTPS URL on its own asset CDN. */
    fun assetRedirect(from: HttpUrl, location: String): HttpUrl {
        require(from.isHttps && from.host == "github.com" && from.port == 443 && assetPath.matches(from.encodedPath) &&
            from.encodedQuery == null && from.fragment == null && from.username.isEmpty() && from.password.isEmpty()) { "更新源重定向已拒绝" }
        val target = AppCatalog.https(location).toHttpUrl()
        require(target.port == 443 && target.host in setOf("release-assets.githubusercontent.com", "objects.githubusercontent.com")) {
            "GitHub 下载重定向到了不受支持的地址"
        }
        return target
    }
}
