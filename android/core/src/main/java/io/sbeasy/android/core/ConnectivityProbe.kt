package io.sbeasy.android.core

import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import okhttp3.Call
import okhttp3.Callback
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

/** Service probe: includes DNS in the deadline and never waits for UI connection observations. */
class ConnectivityProbe(private val client: OkHttpClient = OkHttpClient.Builder()
    .connectTimeout(5, TimeUnit.SECONDS)
    .readTimeout(5, TimeUnit.SECONDS)
    .callTimeout(8, TimeUnit.SECONDS)
    .retryOnConnectionFailure(false)
    .build(), private val timeoutMillis: Long = 10_000) {
    /** Only a failed primary triggers the independent confirmation request. */
    suspend fun checkAny(urls: List<String>): ConnectivityProbeResult {
        require(urls.isNotEmpty())
        val failures = mutableListOf<String>()
        for (url in urls.distinct().take(2)) {
            // Do not include credentials or query strings in diagnostics.
            val host = runCatching { java.net.URI(url).host }.getOrNull() ?: "invalid-host"
            try {
                val status = check(url)
                if (status in 200..399) return ConnectivityProbeResult(true, host, failures)
                failures += "$host: HTTP $status"
            } catch (_: TimeoutCancellationException) {
                currentCoroutineContext().ensureActive()
                failures += "$host: probe deadline exceeded"
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                failures += "$host: ${error.javaClass.simpleName}"
            }
        }
        return ConnectivityProbeResult(false, null, failures)
    }

    suspend fun check(url: String): Int = withTimeout(timeoutMillis) {
        val call = client.newCall(Request.Builder().url(url)
            .header("Cache-Control", "no-cache").header("Connection", "close").get().build())
        suspendCancellableCoroutine { continuation ->
            continuation.invokeOnCancellation { call.cancel() }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    if (continuation.isActive) continuation.resumeWithException(e)
                }
                override fun onResponse(call: Call, response: Response) {
                    val status = response.use { it.code }
                    if (continuation.isActive) continuation.resume(status)
                }
            })
        }
    }
}

data class ConnectivityProbeResult(val healthy: Boolean, val reachedHost: String?, val failures: List<String>)
