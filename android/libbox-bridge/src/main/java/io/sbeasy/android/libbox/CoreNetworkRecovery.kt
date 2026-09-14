package io.sbeasy.android.libbox

internal enum class NetworkRecoveryResult { OBSOLETE, RESET, REBUILT }

/** Keep the existing TUN for handovers; rebuild only on escalation or reset failure. */
internal fun recoverCoreNetwork(
    hasCore: Boolean,
    rebuildRequired: Boolean,
    isCurrent: () -> Boolean,
    reset: () -> Unit,
    rebuild: () -> Unit,
    onResetFailure: (Exception) -> Unit = {},
): NetworkRecoveryResult {
    if (!isCurrent()) return NetworkRecoveryResult.OBSOLETE
    if (hasCore && !rebuildRequired) {
        try {
            reset()
            return if (isCurrent()) NetworkRecoveryResult.RESET else NetworkRecoveryResult.OBSOLETE
        } catch (error: Exception) {
            if (error is java.util.concurrent.CancellationException) throw error
            onResetFailure(error)
        }
    }
    if (!isCurrent()) return NetworkRecoveryResult.OBSOLETE
    rebuild()
    return if (isCurrent()) NetworkRecoveryResult.REBUILT else NetworkRecoveryResult.OBSOLETE
}
