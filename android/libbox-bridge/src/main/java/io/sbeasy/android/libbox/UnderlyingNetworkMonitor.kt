package io.sbeasy.android.libbox

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import io.sbeasy.android.core.ClientDiagnostics
import io.nekohasekai.libbox.InterfaceUpdateListener
import java.net.NetworkInterface

internal class UnderlyingNetworkMonitor(
    context: Context,
    private val onDefaultNetworkChanged: (UnderlyingNetwork?) -> Unit = {},
) {
    private val connectivity = context.getSystemService(ConnectivityManager::class.java)
    private var eventThread: HandlerThread? = null
    private var handler: Handler? = null
    private val lock = Any()
    private var listener: InterfaceUpdateListener? = null
    private var registered = false
    private var callback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var published: UnderlyingNetwork? = null
    val snapshot: UnderlyingNetwork? get() = published
    private data class Facts(
        var capabilities: NetworkCapabilities? = null,
        var links: LinkProperties? = null,
        var blocked: Boolean = false,
    )
    private val networks = mutableMapOf<Network, Facts>()

    @Volatile
    var currentNetwork: Network? = null
        private set

    private val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()

    fun start() = synchronized(lock) {
        if (registered) return@synchronized
        registered = true
        eventThread = HandlerThread("sb-easy-network").also { it.start() }
        handler = Handler(requireNotNull(eventThread).looper)
        // Synchronous reads are startup-only. Callbacks below use their ordered arguments.
        connectivity.allNetworks.forEach { network ->
            val caps = connectivity.getNetworkCapabilities(network)
            if (usable(caps)) networks[network] = Facts(caps, connectivity.getLinkProperties(network))
        }
        val events = object : ConnectivityManager.NetworkCallback() {
            private fun update(action: () -> Unit) = synchronized(lock) {
                if (!registered || callback !== this) return@synchronized
                action()
                publish()
            }
            override fun onAvailable(network: Network) = update {
                networks.putIfAbsent(network, Facts())
                ClientDiagnostics.info(TAG, "network available: network=$network")
            }
            override fun onLost(network: Network) = update {
                networks.remove(network)
                ClientDiagnostics.warn(TAG, "network lost: network=$network")
            }
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) = update {
                networks[network]?.capabilities = capabilities
            }
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = update {
                networks[network]?.links = linkProperties
            }
            override fun onBlockedStatusChanged(network: Network, blocked: Boolean) = update {
                networks[network]?.blocked = blocked
                ClientDiagnostics.info(TAG, "network blocked status: network=$network blocked=$blocked")
            }
        }
        callback = events
        try {
            // Track all eligible networks so losing Wi-Fi can immediately select live cellular.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                connectivity.registerNetworkCallback(request, events, requireNotNull(handler))
            } else {
                connectivity.registerNetworkCallback(request, events)
            }
            publish()
        } catch (error: Exception) {
            registered = false
            callback = null
            networks.clear()
            eventThread?.quitSafely()
            eventThread = null
            handler = null
            throw error
        }
    }

    fun stop() = synchronized(lock) {
        if (!registered) return@synchronized
        registered = false
        callback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        callback = null
        handler?.removeCallbacksAndMessages(null)
        eventThread?.quitSafely()
        eventThread = null
        handler = null
        networks.clear()
        currentNetwork = null
        published = null
        listener = null
        ClientDiagnostics.info(TAG, "default network monitor stopped")
    }

    /** Watchdog reconciliation runs outside callbacks, so synchronous snapshots are safe here. */
    fun reconcile() = synchronized(lock) {
        if (!registered) return@synchronized
        val live = connectivity.allNetworks.toSet()
        networks.keys.retainAll(live)
        live.forEach { network ->
            val caps = connectivity.getNetworkCapabilities(network)
            if (usable(caps)) {
                val facts = networks.getOrPut(network) { Facts() }
                facts.capabilities = caps
                facts.links = connectivity.getLinkProperties(network)
            } else networks.remove(network)
        }
        publish()
    }

    fun setListener(value: InterfaceUpdateListener?) = synchronized(lock) {
        listener = value
        publish(force = true)
    }

    private fun usable(caps: NetworkCapabilities?): Boolean = caps != null &&
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)

    private fun publish(force: Boolean = false, attempt: Int = 0) {
        if (!registered) return
        var missingInterface = false
        val candidates = networks.mapNotNull { (network, facts) ->
            val caps = facts.capabilities
            val links = facts.links
            if (!usable(caps) || links == null) return@mapNotNull null
            val name = links.interfaceName ?: return@mapNotNull null
            val index = runCatching { NetworkInterface.getByName(name)?.index ?: -1 }.getOrDefault(-1)
            if (index < 0) {
                missingInterface = true
                return@mapNotNull null
            }
            val signature = listOf(
                links.linkAddresses.map { it.toString() }.sorted().joinToString(),
                links.dnsServers.map { it.hostAddress.orEmpty() }.sorted().joinToString(),
                links.routes.map { it.toString() }.sorted().joinToString(),
            ).joinToString(";")
            val priority = when {
                caps!!.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 30
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 20
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 10
                else -> 0
            }
            NetworkCandidate(
                UnderlyingNetwork(network.networkHandle, name, index, signature),
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED), priority, facts.blocked,
            )
        }
        if (missingInterface && attempt < 10) {
            val registration = callback
            handler?.postDelayed({ synchronized(lock) {
                if (registered && callback === registration) publish(attempt = attempt + 1)
            } }, 100)
        }
        val selected = preferredNetwork(candidates, published)
        currentNetwork = networks.keys.firstOrNull { it.networkHandle == selected?.handle }
        if (selected == published && !force) return
        val changed = selected != published
        published = selected
        listener?.updateDefaultInterface(selected?.interfaceName.orEmpty(), selected?.interfaceIndex ?: -1, false, false)
        if (changed) {
            ClientDiagnostics.info(TAG, "selected underlying network: handle=${selected?.handle} interface=${selected?.interfaceName}")
            onDefaultNetworkChanged(selected)
        }
    }

    companion object { private const val TAG = "SbEasyNetwork" }
}
