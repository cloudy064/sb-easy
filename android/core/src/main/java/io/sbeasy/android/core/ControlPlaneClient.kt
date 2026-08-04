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
        val response = execute(request)
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

    fun uploadDiagnostics(enrollment: Enrollment, body: JSONObject): String {
        val response = executeAuthenticated(enrollment, "/api/agent/diagnostics", "POST", body)
        response.use {
            val raw = it.body?.string().orEmpty()
            if (!it.isSuccessful) throw apiError(it.code, raw)
            return requireJson(it.code, raw).getString("report_id")
        }
    }

    fun networkSnapshot(): JSONObject {
        val networks = JSONArray()
        preferredUnderlyingNetworks().forEach { network ->
            val capabilities = connectivity.getNetworkCapabilities(network)
            networks.put(
                JSONObject()
                    .put("network", network.toString())
                    .put("interface", connectivity.getLinkProperties(network)?.interfaceName ?: JSONObject.NULL)
                    .put("transport", transports(capabilities))
                    .put("validated", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true)
                    .put("metered", capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false),
            )
        }
        return JSONObject()
            .put("active_network", connectivity.activeNetwork?.toString() ?: JSONObject.NULL)
            .put("underlying_networks", networks)
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
        val response = execute(builder.build())
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
        return execute(builder.build())
    }

    private fun execute(request: Request): okhttp3.Response {
        val primaryError = try {
            // Let Android choose the route first. A Network returned by
            // allNetworks is observable, but the current app UID is not
            // necessarily allowed to bind sockets to it (some vendors return
            // EPERM for inactive cellular networks while Wi-Fi is active).
            return baseClient.newCall(request).execute()
        } catch (error: IOException) {
            ClientDiagnostics.warn(
                "ControlPlane",
                "${request.method} ${request.url.encodedPath} failed on the system default route: ${error.message}",
            )
            error
        }

        // A direct physical-network retry is useful only while our own VPN is
        // active and may be the reason the normal route failed. Outside that
        // state it creates noisy, vendor-specific EPERM failures.
        if (VpnRuntimeState.state.value.phase != VpnPhase.CONNECTED) {
            throw primaryError
        }
        val networks = preferredUnderlyingNetworks()
        networks.forEach { network ->
            val client = baseClient.newBuilder()
                .socketFactory(network.socketFactory)
                .dns(object : Dns {
                    override fun lookup(hostname: String) = network.getAllByName(hostname).toList()
                })
                .build()
            try {
                return client.newCall(request).execute()
            } catch (error: IOException) {
                primaryError.addSuppressed(error)
                ClientDiagnostics.warn(
                    "ControlPlane",
                    "physical fallback failed via ${networkLabel(network)}: ${error.message}",
                )
            }
        }
        throw primaryError
    }

    private fun preferredUnderlyingNetworks(): List<Network> = connectivity.allNetworks
        .mapNotNull { network ->
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
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
        .sortedByDescending { it.second }
        .map { it.first }

    private fun networkLabel(network: Network): String {
        val capabilities = connectivity.getNetworkCapabilities(network)
        return "network=$network interface=${connectivity.getLinkProperties(network)?.interfaceName ?: "unknown"} " +
            "transport=${transports(capabilities)} validated=${capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true}"
    }

    private fun transports(capabilities: NetworkCapabilities?): String = buildList {
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) add("wifi")
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) add("cellular")
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) add("ethernet")
        if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) add("vpn")
    }.ifEmpty { listOf("other") }.joinToString("+")

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
