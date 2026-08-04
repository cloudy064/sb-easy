package io.sbeasy.android.libbox

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import io.sbeasy.android.core.ClientDiagnostics
import io.nekohasekai.libbox.InterfaceUpdateListener
import java.net.NetworkInterface

internal class UnderlyingNetworkMonitor(
    context: Context,
    private val onDefaultInterfaceChanged: (String?) -> Unit = {},
) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val mainHandler = Handler(Looper.getMainLooper())
    private var listener: InterfaceUpdateListener? = null
    private var registered = false
    private var lastPublishedInterface: String? = null

    @Volatile
    var currentNetwork: Network? = null
        private set

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            ClientDiagnostics.info(TAG, "network available: ${describe(network)}")
            select(network)
        }

        override fun onLost(network: Network) {
            ClientDiagnostics.warn(TAG, "network lost: ${describe(network)}")
            if (network == currentNetwork) select(null)
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (network == currentNetwork) {
                ClientDiagnostics.info(TAG, "capabilities changed: ${describe(network, capabilities)}")
            }
            if (network == currentNetwork) publish(network)
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (network == currentNetwork) {
                ClientDiagnostics.info(TAG, "link changed: network=$network interface=${linkProperties.interfaceName ?: "unknown"}")
            }
            if (network == currentNetwork) publish(network)
        }
    }

    private val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()

    fun start() {
        if (registered) return
        registered = true
        ClientDiagnostics.info(TAG, "starting default network monitor on Android ${Build.VERSION.SDK_INT}")
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                connectivity.registerBestMatchingNetworkCallback(request, callback, mainHandler)

            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ->
                connectivity.requestNetwork(request, callback, mainHandler)

            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O ->
                connectivity.registerDefaultNetworkCallback(callback, mainHandler)

            else -> connectivity.registerDefaultNetworkCallback(callback)
        }

        select(
            connectivity.activeNetwork
                ?.takeIf(::isUsableUnderlyingNetwork)
                ?: bestAvailableUnderlyingNetwork(),
        )
    }

    fun stop() {
        if (!registered) return
        registered = false
        runCatching { connectivity.unregisterNetworkCallback(callback) }
        mainHandler.removeCallbacksAndMessages(null)
        currentNetwork = null
        lastPublishedInterface = null
        listener = null
        ClientDiagnostics.info(TAG, "default network monitor stopped")
    }

    fun setListener(value: InterfaceUpdateListener?) {
        listener = value
        publish(currentNetwork)
    }

    private fun bestAvailableUnderlyingNetwork(): Network? = connectivity.allNetworks
        .mapNotNull { network ->
            val capabilities = connectivity.getNetworkCapabilities(network)
                ?: return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            ) {
                return@mapNotNull null
            }
            val score = when {
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 30
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 20
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 10
                else -> 0
            } + if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 100 else 0
            network to score
        }
        .maxByOrNull { it.second }
        ?.first

    private fun isUsableUnderlyingNetwork(network: Network): Boolean {
        val capabilities = connectivity.getNetworkCapabilities(network) ?: return false
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }

    private fun select(network: Network?) {
        if (network == currentNetwork) {
            publish(network)
            return
        }
        currentNetwork = network
        Log.i(TAG, "Default underlying network changed to ${network ?: "none"}")
        ClientDiagnostics.info(TAG, "selected underlying network: ${describe(network)}")
        publish(network)
    }

    private fun publish(network: Network?, attempt: Int = 0) {
        if (network == null) {
            notifyPublishedInterface(null)
            listener?.updateDefaultInterface("", -1, false, false)
            return
        }
        if (network != currentNetwork) return
        val properties = connectivity.getLinkProperties(network)
        val name = properties?.interfaceName
        val index = name?.let {
            runCatching { NetworkInterface.getByName(it)?.index ?: -1 }.getOrDefault(-1)
        } ?: -1
        if ((name == null || index < 0) && attempt < MAX_INTERFACE_LOOKUP_ATTEMPTS) {
            mainHandler.postDelayed({ publish(network, attempt + 1) }, INTERFACE_LOOKUP_DELAY_MS)
            return
        }
        if (name == null || index < 0) {
            Log.w(TAG, "No interface found for underlying network $network")
            ClientDiagnostics.warn(TAG, "interface lookup failed after $attempt attempts for $network")
            return
        }
        val capabilities = connectivity.getNetworkCapabilities(network)
        notifyPublishedInterface(name)
        ClientDiagnostics.info(TAG, "published default interface: name=$name index=$index ${describe(network, capabilities)}")
        // Match SFA: expensive/constrained are informational Apple-network flags,
        // not Android metering. Android interface metering is exposed by getInterfaces().
        listener?.updateDefaultInterface(name, index, false, false)
    }

    private fun notifyPublishedInterface(name: String?) {
        if (name == lastPublishedInterface) return
        lastPublishedInterface = name
        onDefaultInterfaceChanged(name)
    }

    private fun describe(network: Network?, capabilities: NetworkCapabilities? = null): String {
        if (network == null) return "none"
        val caps = capabilities ?: connectivity.getNetworkCapabilities(network)
        val properties = connectivity.getLinkProperties(network)
        val transports = buildList {
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) add("wifi")
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) add("cellular")
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) add("ethernet")
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) add("vpn")
        }.ifEmpty { listOf("other") }.joinToString("+")
        val validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        val metered = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
        return "network=$network interface=${properties?.interfaceName ?: "unknown"} transport=$transports validated=$validated metered=$metered"
    }

    companion object {
        private const val TAG = "SbEasyNetwork"
        private const val MAX_INTERFACE_LOOKUP_ATTEMPTS = 10
        private const val INTERFACE_LOOKUP_DELAY_MS = 100L
    }
}
