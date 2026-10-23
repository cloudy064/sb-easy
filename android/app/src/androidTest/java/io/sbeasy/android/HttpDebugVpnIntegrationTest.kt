package io.sbeasy.android

import android.content.Intent
import android.net.Uri
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import io.nekohasekai.libbox.Libbox
import io.sbeasy.android.core.*
import io.sbeasy.android.libbox.SbEasyVpnService
import java.io.File
import java.net.*
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.UUID
import javax.net.ssl.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in real TUN + plugin test; uses temporary in-process trust, never installs a system CA. */
class HttpDebugVpnIntegrationTest {
    @Test fun vpnOverlayInterceptsThenRestoresHttpsAndRotatesAuthority() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("Requires a disposable device and the dedicated all-IPv4 test profile",
            args.getString("httpDebugVpnIsolatedDevice") == "true")
        val enrollmentUri = args.getString("httpDebugEnrollment").orEmpty()
        assumeTrue("Supply the isolated fixture enrollment", enrollmentUri.isNotBlank())
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull("Grant VPN consent manually before testing", VpnService.prepare(context))
        assertNull("Stop the existing VPN", RuntimeBridge.control)
        assertTrue(HttpDebug.installed(context))
        val repository = CoreGraph.repository
        var enrolledId: String? = null
        try {
            repository.switchMode(ClientMode.MANAGED)
            repository.enroll(enrollmentUri, "http-debug-vpn-test", Libbox.version(), args.getString("httpDebugAllowInsecureLocalHttp") == "true")
            enrolledId = requireNotNull(repository.state.value.enrollment).hostId
            val profile = JSONObject(requireNotNull(repository.activeConfig()).content)
            val tun = profile.getJSONArray("inbounds").let { items ->
                (0 until items.length()).map(items::getJSONObject).first { it.optString("type") == "tun" }
            }
            assertTrue("Use the explicit all-IPv4 fixture profile", tun.getJSONArray("route_address").toString().contains("0.0.0.0/0"))
            assertEquals("Only the host test app may enter this fixture TUN", "[\"${context.packageName}\"]", tun.getJSONArray("include_package").toString())
            CaptureSession.authorize()
            ContextCompat.startForegroundService(context, Intent(context, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_START))
            withTimeout(30_000) { while (VpnRuntimeState.state.value.phase != VpnPhase.CONNECTED) delay(100) }
            val host = "www.example.com"
            val address = InetAddress.getAllByName(host).first { it is Inet4Address }
            val marker = "sb_easy_vpn_probe_${UUID.randomUUID()}"
            fun request(factory: SSLSocketFactory, path: String): String = Socket().use { raw ->
                raw.soTimeout = 20000; raw.connect(InetSocketAddress(address, 443), 15000)
                (factory.createSocket(raw, host, 443, false) as SSLSocket).use { encrypted ->
                    encrypted.soTimeout = 20000
                    encrypted.sslParameters = encrypted.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    encrypted.startHandshake()
                    encrypted.getOutputStream().write("GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
                    encrypted.getInputStream().bufferedReader().readText().also { assertTrue(it.contains("Example Domain")) }
                }
            }
            request(SSLSocketFactory.getDefault() as SSLSocketFactory, "/")
            HttpDebug.start(context)
            val firstCertificate = HttpDebug.certificate()
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(firstCertificate.inputStream())
            val keys = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("temporary-fixture", cert) }
            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(keys) }
            val tls = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
            HttpDebug.attach(host)
            assertTrue(HttpDebug.state.value.attached)
            request(tls.socketFactory, "/?$marker")
            val web = Uri.parse(HttpDebug.state.value.url)
            val token = requireNotNull(web.getQueryParameter("token"))
            fun har(): JSONObject = (URL("http://127.0.0.1:17991/sbeasy.har").openConnection(Proxy.NO_PROXY) as HttpURLConnection).run {
                setRequestProperty("Authorization", "Bearer $token"); connectTimeout = 5000; readTimeout = 5000
                try { assertEquals(200, responseCode); JSONObject(inputStream.bufferedReader().use { it.readText() }) }
                finally { disconnect() }
            }
            withTimeout(10_000) {
                while (true) {
                    val entries = har().getJSONObject("log").getJSONArray("entries")
                    val captured = (0 until entries.length()).map(entries::getJSONObject).firstOrNull {
                        it.getJSONObject("request").getString("url").contains(marker)
                    }
                    if (captured != null) { assertEquals(200, captured.getJSONObject("response").getInt("status")); break }
                    delay(200)
                }
            }
            HttpDebug.stop()
            assertFalse(HttpDebug.state.value.attached)
            val original = requireNotNull(repository.activeConfig()).content
            assertEquals("Stopped capture still applies an overlay", original, HttpDebug.overlay(original))
            withTimeout(10_000) {
                while (listOf(17990, 17991, 17992).any { port ->
                    runCatching { Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300) } }.isSuccess
                }) delay(100)
            }
            request(SSLSocketFactory.getDefault() as SSLSocketFactory, "/")
            HttpDebug.clearLocalAuthority(context)
            HttpDebug.start(context)
            assertFalse("Deleted CA was reused", firstCertificate.contentEquals(HttpDebug.certificate()))
            HttpDebug.stop()
            HttpDebug.verifyCertificateRemoved()
            assertEquals("", HttpDebug.state.value.caFingerprint)
            File(context.getExternalFilesDir(null), "http-debug-vpn-result.txt").writeText(
                "PASS: actual host-app TUN HTTPS through domain overlay, decrypted HAR, ordinary TLS after stop, all three loopback listeners closed, local CA rotation and no tracked CA in Android trust store. The test used temporary process-local trust; system CA installation/removal was NOT RUN.\n")
        } finally {
            runCatching { HttpDebug.stop() }
            if (RuntimeBridge.control != null) {
                context.startService(Intent(context, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_STOP))
                withTimeout(10_000) { while (RuntimeBridge.control != null) delay(100) }
            }
            CaptureSession.end()
            if (enrolledId != null && repository.state.value.enrollment?.hostId == enrolledId) repository.forgetDevice()
        }
    }
}
