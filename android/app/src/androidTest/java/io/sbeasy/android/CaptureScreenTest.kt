package io.sbeasy.android

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import io.sbeasy.android.core.CaptureConfig
import io.sbeasy.android.core.PacketCapture
import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class CaptureScreenTest {
    @get:Rule val compose = createComposeRule()
    @Test fun optInRequiresFilterAndPackagePickerPersists() {
        val previous = PacketCapture.config()
        try {
            PacketCapture.save(CaptureConfig())
            compose.setContent { MaterialTheme { Box(Modifier.width(360.dp).fillMaxSize().background(Color.White)) { CaptureScreen() } } }
            compose.onAllNodes(isToggleable())[0].performClick()
            compose.onNodeWithText("保存并应用").performScrollTo().performClick()
            compose.waitUntil(5000) { compose.onAllNodesWithText("保存失败：开启采集前至少设置一个筛选条件").fetchSemanticsNodes().isNotEmpty() }
            assertFalse(PacketCapture.config().enabled)
            compose.onNodeWithText("选择已安装的应用").performScrollTo().performClick()
            compose.onNodeWithText("搜索应用名称或包名").performTextInput("sb-easy")
            compose.waitUntil(5000) { compose.onAllNodesWithText("io.sbeasy.android", substring = false).fetchSemanticsNodes().isNotEmpty() }
            compose.onNodeWithText("io.sbeasy.android", substring = false).performClick()
            compose.onNodeWithText("确定").performClick()
            compose.onNodeWithText("保存并应用").performScrollTo().performClick()
            compose.waitUntil(5000) { PacketCapture.config().enabled }
            assertEquals(listOf("io.sbeasy.android"), PacketCapture.config().packages)
            compose.onNodeWithText("App 包名，每行一个").assertDoesNotExist()
            compose.onNodeWithText("启用采集").performScrollTo()
            val bitmap = compose.onRoot().captureToImage().asAndroidBitmap()
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            File(context.getExternalFilesDir(null), "capture-settings.png").outputStream().use { bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG,100,it) }
        } finally { PacketCapture.save(previous) }
    }

    @Test fun bpfValidationDoesNotReplaceSavedConfiguration() {
        val previous = PacketCapture.config()
        try {
            PacketCapture.save(CaptureConfig())
            compose.setContent { MaterialTheme { Box(Modifier.width(360.dp).fillMaxSize()) { CaptureScreen() } } }
            compose.onAllNodes(isToggleable())[0].performClick()
            compose.onNodeWithText("BPF 抓包过滤（可选）").performScrollTo().performTextInput("tcp.port == 443")
            compose.onNodeWithText("保存并应用").performScrollTo().performClick()
            compose.waitUntil(5000) { compose.onAllNodesWithText("保存失败：BPF:", substring = true).fetchSemanticsNodes().isNotEmpty() }
            assertEquals(CaptureConfig(), PacketCapture.config())
            compose.onNodeWithText("BPF 抓包过滤（可选）").performScrollTo().performTextReplacement("tcp port 443")
            compose.onNodeWithText("保存并应用").performScrollTo().performClick()
            compose.waitUntil(5000) { PacketCapture.config().enabled }
            assertEquals("tcp port 443", PacketCapture.config().bpf)
            assertTrue(PacketCapture.config().packages.isEmpty())
        } finally { PacketCapture.save(previous) }
    }
}
