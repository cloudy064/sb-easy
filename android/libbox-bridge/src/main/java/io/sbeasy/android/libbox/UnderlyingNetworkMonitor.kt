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
import io.nekohasekai.libbox.InterfaceUpdateListener
import java.net.NetworkInterface

internal class UnderlyingNetworkMonitor(
    context: Context,
) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private val mainHandler = Handler(Looper.getMainLooper())
    private var listener: InterfaceUpdateListener? = null
    private var registered = false

    @Volatile
    var currentNetwork: Network? = null
        private set

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = select(network)

        override fun onLost(network: Network) {
            if (network == currentNetwork) select(null)
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (network == currentNetwork) publish(network)
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
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
        listener = null
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
        publish(network)
    }

    private fun publish(network: Network?, attempt: Int = 0) {
        val target = listener ?: return
        if (network == null) {
            target.updateDefaultInterface("", -1, false, false)
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
            return
        }
        val capabilities = connectivity.getNetworkCapabilities(network)
        val metered = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
        target.updateDefaultInterface(name, index, metered, false)
    }

    companion object {
        private const val TAG = "SbEasyNetwork"
        private const val MAX_INTERFACE_LOOKUP_ATTEMPTS = 10
        private const val INTERFACE_LOOKUP_DELAY_MS = 100L
    }
}
