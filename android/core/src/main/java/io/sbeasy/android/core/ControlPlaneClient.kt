package io.sbeasy.android.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.io.IOException
import java.util.concurrent.TimeUnit
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject

class ControlPlaneException(message: String, val statusCode: Int? = null) : IOException(message)

sealed interface ConfigFetchResult {
    data object NotModified : ConfigFetchResult
    data class Updated(val config: ManagedConfig) : ConfigFetchResult
}

class ControlPlaneClient(context: Context) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val baseClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .callTimeout(30, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    fun parseEnrollmentUri(raw: String): Pair<String, String> {
        return EnrollmentUriParser.parse(raw)
    }

    fun enroll(rawUri: String, device: JSONObject): Enrollment {
        val (server, code) = parseEnrollmentUri(rawUri)
        val body = JSONObject().put("code", code).put("device", device)
        val response = execute(server, "/api/devices/enroll", "POST", body)
        response.use {
            val json = requireJson(it.code, it.body?.string())
            val profile = json.getJSONObject("profile")
            return Enrollment(
                server = EnrollmentUriParser.normalizeServer(json.optString("server", server)),
                hostId = json.getString("host_id"),
                hostName = json.getString("host_name"),
                agentToken = json.getString("agent_token"),
                profileId = profile.getString("id"),
                profileName = profile.getString("name"),
            )
        }
    }

    fun fetchConfig(enrollment: Enrollment, etag: String?, force: Boolean): ConfigFetchResult {
        val request = authenticatedRequest(enrollment, "/api/agent/config")
            .get()
            .apply { if (!force && !etag.isNullOrBlank()) header("If-None-Match", etag) }
            .build()
        val response = execute(enrollment.server, request)
        response.use {
            if (it.code == 304) return ConfigFetchResult.NotModified
            val content = it.body?.string().orEmpty()
            if (!it.isSuccessful) throw apiError(it.code, content)
            require(runCatching { JSONObject(content) }.isSuccess) { "服务器返回了无效配置" }
            return ConfigFetchResult.Updated(
                ManagedConfig(
                    content = content,
                    etag = it.header("ETag").orEmpty(),
                    ruleSource = it.header("X-SB-Easy-Rule-Source") ?: "profile",
                    profileId = it.header("X-SB-Easy-Profile-Id") ?: enrollment.profileId,
                    profileName = it.header("X-SB-Easy-Profile-Name") ?: enrollment.profileName,
                    syncedAtMillis = System.currentTimeMillis(),
                ),
            )
        }
    }

    fun reportStatus(enrollment: Enrollment, body: JSONObject) {
        executeAuthenticated(enrollment, "/api/agent/status", "POST", body).close()
    }

    fun commands(enrollment: Enrollment): List<AgentCommand> {
        val response = executeAuthenticated(enrollment, "/api/agent/commands", "GET", null)
        response.use {
            val raw = it.body?.string().orEmpty()
            if (!it.isSuccessful) throw apiError(it.code, raw)
            val array = JSONArray(raw)
            return buildList {
                for (index in 0 until array.length()) {
                    val item = array.getJSONObject(index)
                    add(AgentCommand(item.getString("id"), item.getString("command")))
                }
            }
        }
    }

    fun acknowledge(enrollment: Enrollment, command: AgentCommand, success: Boolean, result: String) {
        executeAuthenticated(
            enrollment,
            "/api/agent/commands/${command.id}/ack",
            "POST",
            JSONObject().put("status", if (success) "done" else "failed").put("result", result.take(1_000)),
        ).close()
    }

    fun reportTelemetry(enrollment: Enrollment, body: JSONObject) {
        executeAuthenticated(enrollment, "/api/agent/telemetry", "POST", body).close()
    }

    fun reportLatencies(enrollment: Enrollment, values: Map<String, Int?>) {
        val results = JSONObject()
        values.forEach { (tag, delay) -> results.put(tag, delay ?: JSONObject.NULL) }
        executeAuthenticated(
            enrollment,
            "/api/agent/proxy-latency",
            "POST",
            JSONObject().put("results", results),
        ).close()
    }

    private fun executeAuthenticated(
        enrollment: Enrollment,
        path: String,
        method: String,
        body: JSONObject?,
    ): okhttp3.Response {
        val builder = authenticatedRequest(enrollment, path)
        when (method) {
            "GET" -> builder.get()
            "POST" -> builder.post((body ?: JSONObject()).toString().toRequestBody(JSON_MEDIA_TYPE))
            else -> error("Unsupported method")
        }
        val response = execute(enrollment.server, builder.build())
        if (!response.isSuccessful) {
            val raw = response.body?.string().orEmpty()
            response.close()
            throw apiError(response.code, raw)
        }
        return response
    }

    private fun authenticatedRequest(enrollment: Enrollment, path: String): Request.Builder =
        Request.Builder()
            .url(enrollment.server + path)
            .header("Authorization", "Bearer ${enrollment.agentToken}")
            .header("Accept", "application/json")

    private fun execute(server: String, path: String, method: String, body: JSONObject): okhttp3.Response {
        val builder = Request.Builder().url(server + path).header("Accept", "application/json")
        if (method == "POST") builder.post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
        return execute(server, builder.build())
    }

    private fun execute(server: String, request: Request): okhttp3.Response {
        val network = preferredUnderlyingNetwork()
        val client = if (network == null) baseClient else baseClient.newBuilder()
            .socketFactory(network.socketFactory)
            .dns(object : Dns {
                override fun lookup(hostname: String) = network.getAllByName(hostname).toList()
            })
            .build()
        return client.newCall(request).execute()
    }

    private fun preferredUnderlyingNetwork(): Network? = connectivity.allNetworks
        .mapNotNull { network ->
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            ) return@mapNotNull null
            val score = (if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 100 else 0) +
                when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 30
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 20
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 10
                    else -> 0
                }
            network to score
        }
        .maxByOrNull { it.second }
        ?.first

    private fun requireJson(status: Int, raw: String?): JSONObject {
        if (status !in 200..299) throw apiError(status, raw.orEmpty())
        return runCatching { JSONObject(raw.orEmpty()) }
            .getOrElse { throw ControlPlaneException("服务器返回了无效响应", status) }
    }

    private fun apiError(status: Int, raw: String): ControlPlaneException {
        val message = runCatching { JSONObject(raw).optString("error") }.getOrNull()
            ?.takeIf { it.isNotBlank() }
            ?: "控制面请求失败（HTTP $status）"
        return ControlPlaneException(message, status)
    }

    companion object {
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    }
}
