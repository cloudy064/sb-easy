package io.sbeasy.android

import android.content.*
import android.os.*
import androidx.test.platform.app.InstrumentationRegistry
import java.net.*
import java.io.*
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.concurrent.*
import javax.net.ssl.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Device test: standalone Android Python/TLS engine, no VPN or system CA changes. */
class HttpDebugEngineTest {
    @Test fun nativeEngineDecryptsHttpsAndExportsHar() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val main = Handler(Looper.getMainLooper())
        val connected = CountDownLatch(1)
        var peer: Messenger? = null
        val replies = LinkedBlockingQueue<Bundle>()
        val receiver = Messenger(Handler(Looper.getMainLooper()) { replies.offer(it.data); true })
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) { peer = Messenger(binder); connected.countDown() }
            override fun onServiceDisconnected(name: ComponentName) { peer = null }
        }
        fun call(method: String): JSONObject {
            peer!!.send(Message.obtain(null, 1).apply { replyTo = receiver; data = Bundle().apply { putString("method", method) } })
            val reply = requireNotNull(replies.poll(30, TimeUnit.SECONDS)) { "Engine response timed out" }
            check(!reply.containsKey("error")) { reply.getString("error").orEmpty() }
            return JSONObject(reply.getString("result")!!)
        }
        val pool = Executors.newCachedThreadPool()
        val upstream = ServerSocket(17992, 8, InetAddress.getByName("127.0.0.1"))
        pool.submit {
            while (!upstream.isClosed) runCatching {
                val incoming = upstream.accept()
                pool.submit {
                    incoming.use { client ->
                        val reader = client.getInputStream().bufferedReader()
                        val first = reader.readLine(); val destination = first.split(" ")[1].split(":")
                        while (reader.readLine()?.isNotEmpty() == true) { }
                        Socket().use { remote ->
                            remote.connect(InetSocketAddress(destination[0], destination[1].toInt()), 15000)
                            client.getOutputStream().write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
                            val forward = pool.submit { runCatching { client.getInputStream().copyTo(remote.getOutputStream()) } }
                            runCatching { remote.getInputStream().copyTo(client.getOutputStream()) }
                            forward.cancel(true)
                        }
                    }
                }
            }
        }
        try {
            main.post { assertTrue(context.bindService(Intent().setComponent(ComponentName("io.sbeasy.httpdebug", "io.sbeasy.httpdebug.EngineService")), connection, Context.BIND_AUTO_CREATE)) }
            assertTrue(connected.await(15, TimeUnit.SECONDS)); call("start")
            var state = call("snapshot"); val deadline = System.nanoTime()+TimeUnit.SECONDS.toNanos(30)
            while (state.getString("phase") == "starting" && System.nanoTime() < deadline) { Thread.sleep(200); state = call("snapshot") }
            assertEquals(state.optString("error"), "running", state.getString("phase"))
            val certHex = call("certificate").getString("der")
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(certHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()))
            val keys = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("fixture", cert) }
            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(keys) }
            val tls = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
            val password = state.getString("password")
            Socket("127.0.0.1", 17990).use { socket ->
                socket.soTimeout = 20000
                val credential = Base64.getEncoder().encodeToString("sbeasy:$password".toByteArray())
                socket.getOutputStream().write("CONNECT www.example.com:443 HTTP/1.1\r\nHost: www.example.com:443\r\nProxy-Authorization: Basic $credential\r\n\r\n".toByteArray())
                val input = socket.getInputStream(); val head = ByteArrayOutputStream()
                while (!head.toString("US-ASCII").endsWith("\r\n\r\n")) { val b = input.read(); check(b >= 0); head.write(b) }
                assertTrue(head.toString("US-ASCII").contains("200"))
                (tls.socketFactory.createSocket(socket, "www.example.com", 443, false) as SSLSocket).use { encrypted ->
                    encrypted.startHandshake()
                    encrypted.getOutputStream().write("GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n".toByteArray())
                    assertTrue(encrypted.getInputStream().bufferedReader().readText().contains("Example Domain"))
                }
            }
            val token = UriToken(state.getString("url"))
            fun get(path: String): String = (URL("http://127.0.0.1:17991$path").openConnection(Proxy.NO_PROXY) as HttpURLConnection).run {
                setRequestProperty("Authorization", "Bearer $token"); connectTimeout = 5000; readTimeout = 5000
                try {
                    check(responseCode == 200) { "HTTP $responseCode: ${errorStream?.bufferedReader()?.use { it.readText() }?.take(1000)}" }
                    inputStream.bufferedReader().use { it.readText() }
                } finally { disconnect() }
            }
            val flows = JSONArray(get("/flows.json")); assertEquals(1, flows.length())
            val id = flows.getJSONObject(0).getString("id")
            assertTrue(get("/flows/$id/response/content.data").contains("Example Domain"))
            assertEquals(1, JSONObject(get("/sbeasy.har")).getJSONObject("log").getJSONArray("entries").length())
        } finally {
            runCatching { if (peer != null) call("stop") }
            main.post { runCatching { context.unbindService(connection) } }
            upstream.close(); pool.shutdownNow()
        }
    }
    private fun UriToken(url: String) = url.substringAfter("?token=")
}
