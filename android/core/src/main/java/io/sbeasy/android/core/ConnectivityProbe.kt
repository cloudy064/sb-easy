package io.sbeasy.android.core

import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
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
