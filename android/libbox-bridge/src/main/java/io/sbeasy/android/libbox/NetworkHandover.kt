package io.sbeasy.android.libbox

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** A physical network identity, including changes which retain the interface name. */
internal data class UnderlyingNetwork(
    val handle: Long,
    val interfaceName: String,
    val interfaceIndex: Int,
    val linkSignature: String,
)

internal data class NetworkCandidate(
    val network: UnderlyingNetwork,
    val validated: Boolean,
    val transportPriority: Int,
    val blocked: Boolean = false,
)

internal fun preferredNetwork(candidates: List<NetworkCandidate>, current: UnderlyingNetwork?): UnderlyingNetwork? =
    candidates.filterNot { it.blocked }.maxWithOrNull(
        compareBy<NetworkCandidate> { (if (it.validated) 100 else 0) + it.transportPriority }
            .thenBy { it.network == current }
            .thenBy { it.network.handle },
    )?.network

/** Coalesces handovers and invalidates pending/in-flight work when connectivity changes. */
internal class NetworkHandover(
    private val scope: CoroutineScope,
    private val debounceMillis: Long = 1_200,
    private val retryMillis: Long = 2_000,
    private val onPendingChanged: (Boolean) -> Unit = {},
    private val restart: suspend (UnderlyingNetwork, () -> Boolean) -> Boolean,
) {
    @Volatile var pending: Boolean = false
        private set
    private var generation = 0L
    private var current: UnderlyingNetwork? = null
    private var job: Job? = null

    @Synchronized
    fun changed(network: UnderlyingNetwork?, force: Boolean = false) {
        if (current == network && !force) return
        current = network
        val revision = ++generation
        job?.cancel()
        job = null
        pending = network != null
        onPendingChanged(pending)
        if (network == null) return
        job = scope.launch {
            try {
                delay(debounceMillis)
                repeat(3) { attempt ->
                    if (!isCurrent(revision, network)) return@launch
                    if (restart(network) { isCurrent(revision, network) }) return@launch
                    if (attempt < 2) delay(retryMillis)
                }
            } finally {
                synchronized(this@NetworkHandover) {
                    if (generation == revision) { pending = false; onPendingChanged(false) }
                }
            }
        }
    }

    @Synchronized
    fun close() {
        ++generation
        current = null
        pending = false
        onPendingChanged(false)
        job?.cancel()
        job = null
    }

    @Synchronized
    private fun isCurrent(revision: Long, network: UnderlyingNetwork): Boolean =
        generation == revision && current == network
}
