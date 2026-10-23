package io.sbeasy.android

import android.content.*
import android.content.pm.PackageManager
import android.os.*
import androidx.test.platform.app.InstrumentationRegistry
import io.sbeasy.android.core.HttpDebug
import io.sbeasy.android.core.RuntimeBridge
import java.io.File
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Actual OS UID/private-directory enforcement, not a package-metadata mock. */
class PluginSandboxTest {
    @Test fun anotherSignedUidCannotReadHostSecretsOrControlPlugin() {
        assumeTrue("Requires a disposable device and the explicit test-only probe APK",
            InstrumentationRegistry.getArguments().getString("pluginSandboxIsolatedDevice") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull("Stop VPN before the sandbox test", RuntimeBridge.control)
        assertEquals("stopped", HttpDebug.state.value.phase)
        assertTrue(HttpDebug.installed(context))
        val probe = context.packageManager.getApplicationInfo("io.sbeasy.sandboxprobe", 0)
        assertNotEquals(context.applicationInfo.uid, probe.uid)
        assertEquals(PackageManager.SIGNATURE_MATCH, context.packageManager.checkSignatures(context.applicationInfo.uid, probe.uid))
        val canary = File(context.filesDir, "sandbox-probe-${UUID.randomUUID().toString().replace("-", "")}")
        canary.writeText(UUID.randomUUID().toString())
        val connected = CountDownLatch(1)
        var peer: Messenger? = null
        val replies = LinkedBlockingQueue<Bundle>()
        val receiver = Messenger(Handler(Looper.getMainLooper()) { replies.offer(it.data); true })
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) { peer = Messenger(binder); connected.countDown() }
            override fun onServiceDisconnected(name: ComponentName) { peer = null }
        }
        var bound = false
        try {
            bound = context.bindService(Intent().setComponent(ComponentName("io.sbeasy.sandboxprobe", "io.sbeasy.sandboxprobe.ProbeService")), connection, Context.BIND_AUTO_CREATE)
            assertTrue(bound); assertTrue(connected.await(15, TimeUnit.SECONDS))
            requireNotNull(peer).send(Message.obtain(null, 1).apply {
                replyTo = receiver; data = Bundle().apply { putString("canary", canary.absolutePath) }
            })
            val result = requireNotNull(replies.poll(20, TimeUnit.SECONDS)) { "Sandbox probe timed out" }
            assertFalse(result.getString("error"), result.containsKey("error"))
            assertEquals(context.applicationInfo.uid, result.getInt("hostUid"))
            assertEquals(probe.uid, result.getInt("probeUid"))
            assertNotEquals(probe.uid, result.getInt("pluginUid"))
            assertNotEquals(context.applicationInfo.uid, result.getInt("pluginUid"))
            assertTrue("Same-certificate permission prerequisite failed", result.getBoolean("signaturePermissionGranted"))
            assertTrue("Separate UID read host private data", result.getBoolean("privateFileDenied"))
            assertTrue(result.getString("pluginError"), result.getBoolean("hostUidGateRejected"))
            assertTrue(canary.exists())
            File(context.getExternalFilesDir(null), "plugin-sandbox-result.txt").writeText(
                "PASS: three distinct UIDs, same-certificate helper holds signature permission, host private-file read denied, plugin rejects helper through actual host UID gate.\n")
        } finally {
            if (bound) context.unbindService(connection)
            check(canary.delete() || !canary.exists())
        }
    }
}
