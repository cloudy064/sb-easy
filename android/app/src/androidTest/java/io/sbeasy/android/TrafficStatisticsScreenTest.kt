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
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
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
                        listOf(DomainTrafficStat("cdn.example.com", 512, 1024)),
                        packages.associateWith { "名称很长的系统组件 $it" } + ("com.example.browser" to "浏览器"),
                    )
                }
            }
        }
        compose.onNodeWithText("Android 系统").assertIsDisplayed()
        compose.onNodeWithText("↑ 1.0 MB").assertIsDisplayed()
        compose.onNodeWithText("浏览器").assertIsDisplayed()
        screenshot("traffic-apps.png")
        compose.onNodeWithText("Android 系统").performClick()
        compose.onNodeWithText("这些组件共享 UID，流量无法进一步拆分到单个组件。").assertIsDisplayed()
        compose.onNodeWithText("关闭").performClick()
        compose.onNodeWithText("按域名").performClick()
        compose.onNodeWithText("cdn.example.com").assertIsDisplayed()
        screenshot("traffic-domains.png")
        compose.onNodeWithText("搜索域名").performTextInput("does-not-exist")
        compose.onNodeWithText("没有匹配的记录").assertIsDisplayed()
    }

    private fun screenshot(name: String) {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        File(requireNotNull(target.getExternalFilesDir(null)), name).outputStream().use {
            compose.onRoot().captureToImage().asAndroidBitmap().compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it)
        }
    }
}
