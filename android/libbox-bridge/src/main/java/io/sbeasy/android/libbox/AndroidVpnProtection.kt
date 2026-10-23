package io.sbeasy.android.libbox

import android.net.VpnService
import android.os.Build
import java.lang.ref.WeakReference
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

data class AndroidVpnProtectionSnapshot(val alwaysOn: Boolean? = null, val lockdown: Boolean? = null)

/** Read-only system state. A stopped service or old API is unknown, never reported as protection enabled. */
object AndroidVpnProtection {
    private var service = WeakReference<VpnService>(null)
    private val mutable = MutableStateFlow(AndroidVpnProtectionSnapshot())
    val state = mutable.asStateFlow()
    @Synchronized fun attach(value: VpnService) { service = WeakReference(value); refresh() }
    @Synchronized fun detach(value: VpnService) {
        if (service.get() === value) { service.clear(); mutable.value = AndroidVpnProtectionSnapshot() }
    }
    @Synchronized fun refresh() {
        val current = service.get()
        mutable.value = if (Build.VERSION.SDK_INT >= 29 && current != null) runCatching {
            AndroidVpnProtectionSnapshot(current.isAlwaysOn, current.isLockdownEnabled)
        }.getOrDefault(AndroidVpnProtectionSnapshot()) else AndroidVpnProtectionSnapshot()
    }
}
