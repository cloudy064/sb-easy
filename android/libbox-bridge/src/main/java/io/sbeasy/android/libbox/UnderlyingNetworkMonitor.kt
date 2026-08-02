package io.sbeasy.android.libbox

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import io.nekohasekai.libbox.InterfaceUpdateListener
import java.net.NetworkInterface

internal class UnderlyingNetworkMonitor(
    context: Context,
    private val onNetworkChanged: (Network?) -> Unit,
) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private var listener: InterfaceUpdateListener? = null
    private var registered = false

    @Volatile
    var currentNetwork: Network? = null
        private set

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = refresh()
        override fun onLost(network: Network) = refresh()
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) = refresh()
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = refresh()
    }

    fun start() {
        if (registered) return
        registered = true
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        connectivity.registerNetworkCallback(request, callback)
        refresh()
    }

    fun stop() {
        if (!registered) return
        registered = false
        connectivity.unregisterNetworkCallback(callback)
        currentNetwork = null
        listener = null
    }

    fun setListener(value: InterfaceUpdateListener?) {
        listener = value
        publish(currentNetwork)
    }

    private fun refresh() {
        val selected = connectivity.allNetworks
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

        if (selected == currentNetwork) {
            publish(selected)
            return
        }
        currentNetwork = selected
        onNetworkChanged(selected)
        publish(selected)
    }

    private fun publish(network: Network?) {
        val target = listener ?: return
        if (network == null) {
            target.updateDefaultInterface("", -1, false, false)
            return
        }
        val properties = connectivity.getLinkProperties(network) ?: return
        val name = properties.interfaceName ?: return
        val index = runCatching { NetworkInterface.getByName(name)?.index ?: -1 }.getOrDefault(-1)
        val capabilities = connectivity.getNetworkCapabilities(network)
        val metered = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
        target.updateDefaultInterface(name, index, metered, false)
    }
}
