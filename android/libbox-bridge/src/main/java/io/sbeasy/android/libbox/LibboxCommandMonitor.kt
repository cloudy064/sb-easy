package io.sbeasy.android.libbox

import android.util.Log
import io.nekohasekai.libbox.CommandClient
import io.nekohasekai.libbox.CommandClientHandler
import io.nekohasekai.libbox.CommandClientOptions
import io.nekohasekai.libbox.Connection
import io.nekohasekai.libbox.ConnectionEvents
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LogIterator
import io.nekohasekai.libbox.OutboundGroupIterator
import io.nekohasekai.libbox.StatusMessage
import io.nekohasekai.libbox.StringIterator
import io.sbeasy.android.core.ConnectionSnapshot
import io.sbeasy.android.core.ProxyGroupSnapshot
import io.sbeasy.android.core.ProxyItemSnapshot
import io.sbeasy.android.core.RuntimeLog
import io.sbeasy.android.core.RuntimeObservability
import io.sbeasy.android.core.TrafficSnapshot

internal class LibboxCommandMonitor(
    private val onGroupsUpdated: (List<ProxyGroupSnapshot>) -> Unit = {},
) : CommandClientHandler {
    private val connections = linkedMapOf<String, ConnectionSnapshot>()
    private var client: CommandClient? = null

    fun connect() {
        if (client != null) return
        val options = CommandClientOptions().apply {
            addCommand(Libbox.CommandStatus)
            addCommand(Libbox.CommandGroup)
            addCommand(Libbox.CommandLog)
            addCommand(Libbox.CommandConnections)
            statusInterval = 1_000_000_000L
        }
        client = Libbox.newCommandClient(this, options).also { it.connect() }
    }

    fun close() {
        client?.let { runCatching { it.disconnect() } }
        client = null
        connections.clear()
        RuntimeObservability.resetRuntime()
    }

    fun selectOutbound(groupTag: String, outboundTag: String) {
        requireNotNull(client) { "libbox command client is disconnected" }
            .selectOutbound(groupTag, outboundTag)
    }

    fun urlTest(groupTag: String) {
        requireNotNull(client) { "libbox command client is disconnected" }.urlTest(groupTag)
    }

    fun clearRuntimeLogs() {
        requireNotNull(client) { "libbox command client is disconnected" }.clearLogs()
    }

    override fun connected() {
        Log.i(TAG, "libbox command stream connected")
    }

    override fun disconnected(message: String?) {
        Log.w(TAG, "libbox command stream disconnected: ${message.orEmpty()}")
    }

    override fun setDefaultLogLevel(level: Int) = Unit

    override fun clearLogs() = RuntimeObservability.clearLogs()

    override fun writeLogs(messageList: LogIterator?) {
        if (messageList == null) return
        val values = buildList {
            while (messageList.hasNext()) {
                val entry = messageList.next()
                add(RuntimeLog(entry.level, entry.message.orEmpty()))
            }
        }
        RuntimeObservability.appendLogs(values)
    }

    override fun writeStatus(message: StatusMessage) {
        RuntimeObservability.updateTraffic(
            TrafficSnapshot(
                uplink = message.uplink,
                downlink = message.downlink,
                uplinkTotal = message.uplinkTotal,
                downlinkTotal = message.downlinkTotal,
                connectionsIn = message.connectionsIn,
                connectionsOut = message.connectionsOut,
                memory = message.memory,
                goroutines = message.goroutines,
            ),
        )
    }

    override fun writeGroups(message: OutboundGroupIterator?) {
        if (message == null) return
        val groups = buildList {
            while (message.hasNext()) {
                val group = message.next()
                val iterator = group.items
                val items = buildList {
                    while (iterator.hasNext()) {
                        val item = iterator.next()
                        add(
                            ProxyItemSnapshot(
                                tag = item.tag.orEmpty(),
                                type = item.type.orEmpty(),
                                urlTestTime = item.urlTestTime,
                                urlTestDelay = item.urlTestDelay,
                            ),
                        )
                    }
                }
                add(
                    ProxyGroupSnapshot(
                        tag = group.tag.orEmpty(),
                        type = group.type.orEmpty(),
                        selectable = group.selectable,
                        selected = group.selected.orEmpty(),
                        items = items,
                    ),
                )
            }
        }
        RuntimeObservability.updateGroups(groups)
        onGroupsUpdated(groups)
    }

    override fun initializeClashMode(modeList: StringIterator?, currentMode: String?) = Unit

    override fun updateClashMode(newMode: String?) = Unit

    override fun writeConnectionEvents(events: ConnectionEvents?) {
        if (events == null) return
        if (events.reset) connections.clear()
        val iterator = events.iterator()
        while (iterator.hasNext()) {
            val event = iterator.next()
            when (event.type.toLong()) {
                Libbox.ConnectionEventNew -> event.connection?.let {
                    connections[event.id] = it.toSnapshot()
                }
                Libbox.ConnectionEventUpdate -> connections[event.id]?.let { current ->
                    connections[event.id] = current.copy(
                        uplink = event.uplinkDelta,
                        downlink = event.downlinkDelta,
                        uplinkTotal = current.uplinkTotal + event.uplinkDelta,
                        downlinkTotal = current.downlinkTotal + event.downlinkDelta,
                    )
                }
                Libbox.ConnectionEventClosed -> {
                    val closed = event.connection?.toSnapshot()
                    if (closed != null) connections[event.id] = closed
                    else connections[event.id]?.let { connections[event.id] = it.copy(closedAt = event.closedAt) }
                }
            }
        }
        val cutoff = System.currentTimeMillis() - 5 * 60_000L
        connections.entries.removeAll { it.value.closedAt in 1 until cutoff }
        RuntimeObservability.updateConnections(connections.values.toList())
    }

    private fun Connection.toSnapshot(): ConnectionSnapshot {
        val chainIterator = chain()
        val chain = buildList {
            while (chainIterator.hasNext()) add(chainIterator.next().orEmpty())
        }
        return ConnectionSnapshot(
            id = id.orEmpty(),
            network = network.orEmpty(),
            source = source.orEmpty(),
            destination = destination.orEmpty(),
            domain = domain.orEmpty(),
            protocol = protocol.orEmpty(),
            createdAt = createdAt,
            closedAt = closedAt,
            uplink = uplink,
            downlink = downlink,
            uplinkTotal = uplinkTotal,
            downlinkTotal = downlinkTotal,
            rule = rule.orEmpty(),
            outbound = outbound.orEmpty(),
            outboundType = outboundType.orEmpty(),
            chain = chain,
        )
    }

    companion object {
        private const val TAG = "SbEasyCommandMonitor"
    }
}
