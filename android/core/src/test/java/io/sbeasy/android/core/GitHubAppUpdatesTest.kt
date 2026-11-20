package io.sbeasy.android.core

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class GitHubAppUpdatesTest {
    private val arm = AndroidUpdateAsset("android-v1.4.1", "arm64-v8a")
    private val abis = listOf("arm64-v8a", "armeabi-v7a")
    private fun hint() = JSONObject().put("tag", arm.tag).put("abi", arm.abi)
        .put("apk_url", arm.apkUrl).put("catalog_url", arm.catalogUrl)

    @Test fun anonymousCenterCheckPreservesBasePathAndRejectsUnrelatedAssets() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody(hint().toString()))
            val result = AppUpdateTransfer().discover(server.url("/panel/").toString(), abis)
            assertEquals(arm to true, result)
            val request = server.takeRequest()
            assertEquals("/panel/api/agent/android-update/arm64-v8a,armeabi-v7a", request.path)
            assertNull(request.getHeader("Authorization"))
            assertNull(request.getHeader("Cookie"))
        }
        for ((key, value) in listOf("catalog_url" to "https://other.test/catalog",
            "apk_url" to arm.apkUrl.replace("cloudy064", "other"), "tag" to "../foo", "abi" to "x86")) {
            assertTrue(runCatching { GitHubAppUpdates.fromCenter(hint().put(key, value), abis) }.isFailure)
        }
    }

    @Test fun standaloneInventoryChoosesPreferredAbiThenUniversal() {
        val universal = arm.copy(abi = "universal")
        val assets = JSONArray().put(JSONObject().put("url", universal.apkUrl)).put(JSONObject().put("url", arm.apkUrl))
        val json = JSONObject().put("published", JSONObject().put("android", JSONObject().put("tag", arm.tag).put("artifacts", assets)))
        assertEquals(arm, GitHubAppUpdates.fromInventory(json, abis))
        assertEquals(universal, GitHubAppUpdates.fromInventory(json, listOf("x86")))
    }

    @Test fun onlyOfficialReleaseUrlsCanRedirectToTheGitHubAssetCdn() {
        val from = arm.catalogUrl.toHttpUrl()
        val target = "https://release-assets.githubusercontent.com/github-production-release-asset/123?signature=example"
        assertEquals(target.toHttpUrl(), GitHubAppUpdates.assetRedirect(from, target))
        for (url in listOf(target.replace("https:", "http:"), target.replace(".com/", ".com.other.test/"),
            target.replace(".com/", ".com:8443/"), target.replace("https://", "https://user@"))) {
            assertTrue(runCatching { GitHubAppUpdates.assetRedirect(from, url) }.isFailure)
        }
        for (url in listOf(arm.apkUrl.replace("cloudy064", "other"), arm.apkUrl + "?next=1", target)) {
            assertTrue(runCatching { GitHubAppUpdates.assetRedirect(url.toHttpUrl(), target) }.isFailure)
        }
    }
}
