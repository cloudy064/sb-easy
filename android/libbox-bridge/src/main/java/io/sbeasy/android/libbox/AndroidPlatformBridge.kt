/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Platform integration follows the public PlatformInterface contract and the
 * sing-box for Android implementation at release 1.13.12.
 */
package io.sbeasy.android.libbox

import android.content.Context
import android.content.pm.PackageManager.NameNotFoundException
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.Notification
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.RoutePrefix
import io.nekohasekai.libbox.RoutePrefixIterator
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.InterfaceAddress
import java.net.NetworkInterface
import java.security.KeyStore
import io.nekohasekai.libbox.NetworkInterface as LibboxNetworkInterface

internal class AndroidPlatformBridge(
    private val service: SbEasyVpnService,
) : PlatformInterface {
    private val connectivity = service.getSystemService(ConnectivityManager::class.java)
    private val networkMonitor = UnderlyingNetworkMonitor(service) { network ->
        service.updateUnderlyingNetwork(network)
    }

    fun start() = networkMonitor.start()

    fun stop() = networkMonitor.stop()

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun autoDetectInterfaceControl(fd: Int) {
        check(service.protect(fd)) { "android: failed to protect outbound socket" }
    }

    override fun openTun(options: TunOptions): Int {
        check(VpnService.prepare(service) == null) { "android: missing VPN permission" }

        val builder = service.Builder()
            .setSession("sb-easy managed proxy")
            .setMtu(options.mtu)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        networkMonitor.currentNetwork?.let { builder.setUnderlyingNetworks(arrayOf(it)) }

        val inet4Addresses = options.inet4Address.drain()
        val inet6Addresses = options.inet6Address.drain()
        (inet4Addresses + inet6Addresses).forEach { prefix ->
            builder.addAddress(prefix.address(), prefix.prefix())
        }

        if (options.autoRoute) {
            builder.addDnsServer(options.dnsServerAddress.value)
            addRoutes(builder, options, inet4Addresses.isNotEmpty(), inet6Addresses.isNotEmpty())
            addApplicationFilters(builder, options)
        }

        val descriptor = builder.establish()
            ?: error("android: VPN permission was revoked before TUN establishment")
        service.attachTun(descriptor)
        return descriptor.fd
    }

    private fun addRoutes(
        builder: VpnService.Builder,
        options: TunOptions,
        hasIPv4: Boolean,
        hasIPv6: Boolean,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val ipv4Routes = options.inet4RouteAddress.drain()
            val ipv6Routes = options.inet6RouteAddress.drain()
            if (ipv4Routes.isEmpty() && hasIPv4) builder.addRoute("0.0.0.0", 0)
            if (ipv6Routes.isEmpty() && hasIPv6) builder.addRoute("::", 0)
            ipv4Routes.forEach { builder.addRoute(it.toIpPrefix()) }
            ipv6Routes.forEach { builder.addRoute(it.toIpPrefix()) }
            options.inet4RouteExcludeAddress.drain().forEach { builder.excludeRoute(it.toIpPrefix()) }
            options.inet6RouteExcludeAddress.drain().forEach { builder.excludeRoute(it.toIpPrefix()) }
            return
        }

        options.inet4RouteRange.drain().forEach { builder.addRoute(it.address(), it.prefix()) }
        options.inet6RouteRange.drain().forEach { builder.addRoute(it.address(), it.prefix()) }
    }

    private fun addApplicationFilters(builder: VpnService.Builder, options: TunOptions) {
        options.includePackage.drainStrings().forEach { packageName ->
            try {
                builder.addAllowedApplication(packageName)
            } catch (error: NameNotFoundException) {
                Log.w(TAG, "Ignoring missing allowed package $packageName", error)
            }
        }
        options.excludePackage.drainStrings().forEach { packageName ->
            try {
                builder.addDisallowedApplication(packageName)
            } catch (error: NameNotFoundException) {
                Log.w(TAG, "Ignoring missing excluded package $packageName", error)
            }
        }
    }

    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q

    @RequiresApi(Build.VERSION_CODES.Q)
    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): ConnectionOwner {
        val uid = connectivity.getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort),
        )
        check(uid != Process.INVALID_UID) { "android: connection owner not found" }
        val packages = service.packageManager.getPackagesForUid(uid).orEmpty()
        return ConnectionOwner().apply {
            userId = uid
            userName = packages.firstOrNull().orEmpty()
            setAndroidPackageNames(StringArray(packages.toList()))
        }
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        networkMonitor.setListener(listener)
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        networkMonitor.setListener(null)
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val javaInterfaces = NetworkInterface.getNetworkInterfaces().toList()
        val result = connectivity.allNetworks.mapNotNull { network ->
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                return@mapNotNull null
            }
            val properties = connectivity.getLinkProperties(network) ?: return@mapNotNull null
            val name = properties.interfaceName ?: return@mapNotNull null
            val javaInterface = javaInterfaces.find { it.name == name } ?: return@mapNotNull null
            LibboxNetworkInterface().apply {
                this.name = name
                index = javaInterface.index
                mtu = runCatching { javaInterface.mtu }.getOrDefault(1_500)
                addresses = StringArray(javaInterface.interfaceAddresses.map { it.toPrefix() })
                dnsServer = StringArray(properties.dnsServers.mapNotNull { it.hostAddress })
                type = when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                    else -> Libbox.InterfaceTypeOther
                }
                flags = flagsFor(javaInterface, capabilities)
                metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            }
        }
        return InterfaceArray(result)
    }

    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    override fun readWIFIState(): WIFIState? = null

    override fun localDNSTransport(): LocalDNSTransport? = null

    override fun systemCertificates(): StringIterator {
        val keyStore = KeyStore.getInstance("AndroidCAStore")
        keyStore.load(null, null)
        val values = buildList {
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val certificate = keyStore.getCertificate(aliases.nextElement()) ?: continue
                val encoded = Base64.encodeToString(certificate.encoded, Base64.NO_WRAP)
                add("-----BEGIN CERTIFICATE-----\n$encoded\n-----END CERTIFICATE-----")
            }
        }
        return StringArray(values)
    }

    override fun clearDNSCache() = Unit

    override fun sendNotification(notification: Notification) {
        Log.i(TAG, "libbox notification: ${notification.title}: ${notification.body}")
    }

    private fun flagsFor(
        networkInterface: NetworkInterface,
        capabilities: NetworkCapabilities,
    ): Int {
        var flags = 0
        if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
            flags = flags or OsConstants.IFF_UP or OsConstants.IFF_RUNNING
        }
        if (networkInterface.isLoopback) flags = flags or OsConstants.IFF_LOOPBACK
        if (networkInterface.isPointToPoint) flags = flags or OsConstants.IFF_POINTOPOINT
        if (networkInterface.supportsMulticast()) flags = flags or OsConstants.IFF_MULTICAST
        return flags
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun RoutePrefix.toIpPrefix(): IpPrefix =
        IpPrefix(InetAddress.getByName(address()), prefix())

    private fun InterfaceAddress.toPrefix(): String = if (address is Inet6Address) {
        "${Inet6Address.getByAddress(address.address).hostAddress}/$networkPrefixLength"
    } else {
        "${address.hostAddress}/$networkPrefixLength"
    }

    private fun RoutePrefixIterator.drain(): List<RoutePrefix> = buildList {
        while (hasNext()) add(next())
    }

    private fun StringIterator.drainStrings(): List<String> = buildList {
        while (hasNext()) add(next())
    }

    companion object {
        private const val TAG = "SbEasyPlatform"
    }
}
