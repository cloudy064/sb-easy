package io.sbeasy.android

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import io.sbeasy.android.core.AppTrafficLedger
import io.sbeasy.android.core.ConnectionSnapshot
import io.sbeasy.android.core.TrafficDetailKey
import io.sbeasy.android.core.TrafficDetailStat
import io.sbeasy.android.core.TrafficRoute
import io.sbeasy.android.core.AppTrafficStat
import io.sbeasy.android.core.DomainTrafficStat
import java.io.File
import org.junit.Rule
import org.junit.Test

class TrafficStatisticsScreenTest {
    @get:Rule val compose = createComposeRule()

    @Test fun sharedSystemGroupStaysCompactAndDomainSwitchShowsIndependentTotals() {
        val packages = (1..50).map { "com.android.component$it" }
        compose.setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Box(Modifier.width(360.dp).fillMaxSize().background(Color(0xFF090E14))) {
                    TrafficStatisticsContent(
                        listOf(AppTrafficStat("system", 1000, packages, 1_048_576, 2_097_152),
                            AppTrafficStat("browser", 10001, listOf("com.example.browser"), 1024, 2048)),
                        listOf(DomainTrafficStat("example.com", 512, 1024)),
                        packages.associateWith { "名称很长的系统组件 $it" } + ("com.example.browser" to "浏览器"),
                        listOf(TrafficDetailStat(TrafficDetailKey("browser", "example.com", "cdn.example.com", TrafficRoute.DIRECT, "direct", "direct"), 512, 1024)),
                    )
                }
            }
        }
        compose.onNodeWithText("Android 系统").assertIsDisplayed()
        compose.onNodeWithText("↑ 1.0 MB").assertIsDisplayed()
        compose.onNodeWithText("浏览器").assertIsDisplayed()
        screenshot("traffic-apps.png")
        compose.onNodeWithText("Android 系统").performClick()
        compose.onNodeWithText("应用信息").performClick()
        compose.onNodeWithText("这些组件共享 UID，流量无法进一步拆分到单个组件。").assertIsDisplayed()
        compose.onNodeWithText("关闭").performClick()
        compose.onNodeWithText("‹ 返回").performClick()
        compose.onNodeWithText("按域名").performClick()
        compose.onNodeWithText("example.com").assertIsDisplayed()
        screenshot("traffic-domains.png")
        compose.onNodeWithText("搜索主域名，例如 example.com").performTextInput("does-not-exist")
        compose.onNodeWithText("没有匹配的记录").assertIsDisplayed()
    }

    @Test fun applicationsAndDomainsDrillIntoHostsAndActualProxyExits() {
        val ledger = AppTrafficLedger()
        fun record(id: String, host: String, outbound: String, type: String, up: Long, uid: Int = 10001) {
            ledger.record(ConnectionSnapshot(id, "tcp", "", "", host, "tls", 1, 0, 0, 0, up, up * 2,
                "", outbound, type, if (type == "direct") listOf("direct") else listOf(outbound, "默认代理"),
                uid, listOf(if (uid == 10001) "com.example.browser" else "com.example.other")))
        }
        record("proxy", "api.example.co.uk", "东京", "http", 1_048_576)
        record("direct", "api.example.co.uk", "direct", "direct", 524_288)
        record("cdn", "cdn.example.co.uk", "美国", "trojan", 262_144)
        record("other", "api.example.co.uk", "direct", "direct", 131_072, 10002)
        val state = ledger.statistics()
        compose.setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Box(Modifier.width(360.dp).fillMaxSize().background(Color(0xFF090E14))) {
                    TrafficStatisticsContent(state.apps, state.domains,
                        mapOf("com.example.browser" to "浏览器", "com.example.other" to "另一个应用"), state.details)
                }
            }
        }
        compose.onNodeWithText("浏览器").performClick()
        compose.onNodeWithText("api.example.co.uk").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("代理 · 东京").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("直连").performScrollTo().assertIsDisplayed()
        screenshot("traffic-app-hosts.png")
        compose.onNodeWithText("api.example.co.uk").performClick()
        compose.onNodeWithText("代理 · 东京").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("默认代理 → 东京").performScrollTo().assertIsDisplayed()
        screenshot("traffic-host-exits.png")
        compose.onNodeWithText("直连").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("‹ 返回").performClick()
        compose.onNodeWithText("‹ 返回").performClick()
        compose.onNodeWithText("按域名").performClick()
        compose.onNodeWithText("example.co.uk").assertIsDisplayed()
        compose.onNodeWithText("api.example.co.uk").assertDoesNotExist()
        screenshot("traffic-root-domains.png")
        compose.onNodeWithText("example.co.uk").performClick()
        compose.onNodeWithText("api.example.co.uk").performScrollTo().assertIsDisplayed()
        screenshot("traffic-domain-hosts.png")
        compose.onNodeWithText("cdn.example.co.uk").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("代理 · 美国").performScrollTo().assertIsDisplayed()
    }

    private fun screenshot(name: String) {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        File(requireNotNull(target.getExternalFilesDir(null)), name).outputStream().use {
            compose.onRoot().captureToImage().asAndroidBitmap().compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)
        }
    }
}
