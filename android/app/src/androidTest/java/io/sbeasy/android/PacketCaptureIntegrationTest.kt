package io.sbeasy.android

import android.content.Intent
import android.net.VpnService
import androidx.test.platform.app.InstrumentationRegistry
import androidx.core.content.ContextCompat
import io.nekohasekai.libbox.Libbox
import io.sbeasy.android.core.*
import io.sbeasy.android.libbox.SbEasyVpnService
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Socket
import java.net.DatagramSocket
import java.net.DatagramPacket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Opt-in device test against an isolated panel + HTTP echo fixture. */
class PacketCaptureIntegrationTest {
    @Test fun tunPacketsAreFilteredSealedAndUploaded() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("Use only a disposable, explicitly isolated test device", args.getString("captureIsolatedDevice") == "true")
        val uri = args.getString("captureEnrollment").orEmpty()
        assumeTrue("Supply an isolated capture enrollment", uri.isNotBlank())
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertNull("Grant the test device VPN permission first", VpnService.prepare(context))
        assertNull("Stop any existing VPN before running this test", RuntimeBridge.control)
        CoreGraph.repository.switchMode(ClientMode.MANAGED)
        CoreGraph.repository.enroll(uri, "capture-test", Libbox.version(), args.getString("captureAllowInsecureLocalHttp") == "true")
        val enrollment = requireNotNull(CoreGraph.repository.state.value.enrollment)
        PacketCapture.files(enrollment).forEach { PacketCapture.delete(it) }
        val address = args.getString("captureAddress") ?: "192.168.240.1"
        val fixtureAddress = InetAddress.getByName(address).address
        require(fixtureAddress.size == 4) { "The capture fixture currently requires an IPv4 LAN address" }
        val port = args.getString("capturePort") ?: "18999"
        suspend fun request(host: String, marker: String) {
            Socket().use { socket ->
                socket.soTimeout = 10_000
                socket.connect(InetSocketAddress(address, port.toInt()), 10_000)
                socket.getOutputStream().write("GET /$marker HTTP/1.1\r\nHost: $host:$port\r\nConnection: close\r\n\r\n".toByteArray())
                val response = socket.getInputStream().bufferedReader().readText()
                assertTrue(response, response.startsWith("HTTP/1.0 200") || response.startsWith("HTTP/1.1 200"))
                assertTrue(response.contains(marker))
            }
            delay(300)
        }
        suspend fun configure(config: CaptureConfig) {
            CoreGraph.repository.saveCaptureConfiguration(config)
            if (RuntimeBridge.control == null) {
                ContextCompat.startForegroundService(context, Intent(context, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_START))
            }
            withTimeout(30_000) { while (VpnRuntimeState.state.value.phase != VpnPhase.CONNECTED) delay(100) }
            delay(500)
        }
        CaptureSession.authorize()
        try {
            configure(CaptureConfig(enabled = true, domains = listOf("capture.test"), wifiOnly = false))
            request("api.capture.test", "DOMAIN-POSITIVE-12345")
            request("other.test", "DOMAIN-NEGATIVE-12345")
            PacketCapture.rotate()
            var files = PacketCapture.files(enrollment)
            assertTrue("No PCAP: ${PacketCapture.nativeStatus()} ${PacketCapture.runtimeError}", files.isNotEmpty())
            var all = files.flatMap { it.file.readBytes().toList() }.toByteArray().toString(Charsets.ISO_8859_1)
            assertTrue("domain positive absent", all.contains("DOMAIN-POSITIVE-12345"))
            assertFalse("unmatched host leaked", all.contains("DOMAIN-NEGATIVE-12345"))
            files.forEach { validatePcap(it.file.readBytes(), fixtureAddress) }
            CoreGraph.repository.uploadCaptures()
            assertTrue(PacketCapture.uploadStatus, PacketCapture.files(enrollment).all { it.uploaded })

            files.forEach { PacketCapture.delete(it) }
            configure(CaptureConfig(enabled = true, hosts = listOf("exact.capture.test"), wifiOnly = false))
            request("exact.capture.test", "HOST-POSITIVE-67890")
            request("sub.exact.capture.test", "HOST-NEGATIVE-67890")
            PacketCapture.rotate()
            files = PacketCapture.files(enrollment)
            all = files.flatMap { it.file.readBytes().toList() }.toByteArray().toString(Charsets.ISO_8859_1)
            assertTrue("exact host absent", all.contains("HOST-POSITIVE-67890"))
            assertFalse("subdomain matched exact host", all.contains("HOST-NEGATIVE-67890"))
            files.forEach { PacketCapture.delete(it) }

            configure(CaptureConfig(enabled = true, packages = listOf(context.packageName), wifiOnly = false))
            request("other.test", "APP-POSITIVE-24680")
            DatagramSocket().use { socket ->
                socket.soTimeout = 10_000
                val data = "UDP-APP-POSITIVE-13579".toByteArray()
                socket.send(DatagramPacket(data, data.size, InetAddress.getByName(address), (args.getString("captureUdpPort") ?: "18998").toInt()))
                val answer = DatagramPacket(ByteArray(2048), 2048)
                socket.receive(answer)
                assertEquals("UDP-APP-POSITIVE-13579", String(answer.data, 0, answer.length))
            }
            delay(300)
            PacketCapture.rotate()
            files = PacketCapture.files(enrollment)
            all = files.flatMap { it.file.readBytes().toList() }.toByteArray().toString(Charsets.ISO_8859_1)
            assertTrue("app UID attribution absent", all.contains("APP-POSITIVE-24680"))
            assertTrue("UDP capture absent", all.contains("UDP-APP-POSITIVE-13579"))
            CoreGraph.repository.uploadCaptures()
            assertTrue(PacketCapture.uploadStatus, PacketCapture.files(enrollment).all { it.uploaded })
            files.forEach { PacketCapture.delete(it) }
            configure(CaptureConfig(enabled = true, packages = listOf(context.packageName), bpf = "udp", wifiOnly = false))
            request("other.test", "BPF-EXCLUDED-TCP-13579")
            DatagramSocket().use { socket ->
                socket.soTimeout = 10_000
                val data = "BPF-INCLUDED-UDP-13579".toByteArray()
                socket.send(DatagramPacket(data, data.size, InetAddress.getByName(address), (args.getString("captureUdpPort") ?: "18998").toInt()))
                val answer = DatagramPacket(ByteArray(2048), 2048)
                socket.receive(answer)
                assertEquals(String(data), String(answer.data, 0, answer.length))
            }
            delay(300)
            PacketCapture.rotate()
            files = PacketCapture.files(enrollment)
            all = files.flatMap { it.file.readBytes().toList() }.toByteArray().toString(Charsets.ISO_8859_1)
            assertTrue("BPF UDP missing", all.contains("BPF-INCLUDED-UDP-13579"))
            assertFalse("BPF excluded TCP leaked", all.contains("BPF-EXCLUDED-TCP-13579"))
            assertTrue(org.json.JSONObject(PacketCapture.nativeStatus()).getLong("filtered") > 0)
            files.forEach { PacketCapture.delete(it) }
            configure(CaptureConfig(enabled = true, bpf = "tcp port $port", wifiOnly = false))
            request("other.test", "BPF-ONLY-TCP-24680")
            PacketCapture.rotate()
            files = PacketCapture.files(enrollment)
            all = files.flatMap { it.file.readBytes().toList() }.toByteArray().toString(Charsets.ISO_8859_1)
            assertTrue("BPF-only capture missing", all.contains("BPF-ONLY-TCP-24680"))
            files.forEach { validatePcap(it.file.readBytes(), fixtureAddress) }
            CoreGraph.repository.uploadCaptures()
            assertTrue(PacketCapture.uploadStatus, PacketCapture.files(enrollment).all { it.uploaded })
            java.io.File(context.getExternalFilesDir(null), "capture-integration-result.txt").writeText("PASS: domain suffix, exact host, package attribution, TCP handshake, bidirectional TCP/UDP, native BPF conjunction and exclusion, BPF-only capture, PCAP upload")
        } finally {
            context.startService(Intent(context, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_STOP))
            withTimeout(10_000) { while (RuntimeBridge.control != null) delay(100) }
            PacketCapture.endSession()
            if (CoreGraph.repository.state.value.enrollment?.hostId == enrollment.hostId) {
                CoreGraph.repository.forgetDevice()
            }
        }
    }
    private fun validatePcap(data: ByteArray, fixtureAddress: ByteArray) {
        val b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(0xa1b2c3d4.toInt(), b.int)
        assertEquals(101, b.getInt(20))
        var offset = 24
        var outbound = false
        var inbound = false
        var syn = false
        while (offset < data.size) {
            val length = b.getInt(offset + 8)
            assertEquals(length, b.getInt(offset + 12))
            assertTrue(length in 20..65535 && offset + 16 + length <= data.size)
            val ip = offset + 16
            if ((data[ip].toInt() and 0xf0) == 0x40 && data[ip + 9].toInt() == 6) {
                val tcp = ip + (data[ip].toInt() and 15) * 4
                if (data[tcp+13].toInt() and 2 != 0) syn = true
                if (data.copyOfRange(ip + 12, ip + 16).contentEquals(fixtureAddress)) inbound = true
                if (data.copyOfRange(ip + 16, ip + 20).contentEquals(fixtureAddress)) outbound = true
            }
            offset += 16 + length
        }
        assertEquals(data.size, offset)
        assertTrue("missing outgoing packets", outbound)
        assertTrue("missing incoming packets", inbound)
        assertTrue("missing TCP handshake", syn)
    }
}
