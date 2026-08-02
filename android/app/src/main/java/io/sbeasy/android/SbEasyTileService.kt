package io.sbeasy.android

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import io.sbeasy.android.core.VpnPhase
import io.sbeasy.android.core.VpnRuntimeState
import io.sbeasy.android.libbox.SbEasyVpnService

class SbEasyTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (VpnRuntimeState.state.value.phase == VpnPhase.CONNECTED) {
            startService(Intent(this, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_STOP))
            qsTile?.state = Tile.STATE_INACTIVE
            qsTile?.updateTile()
            return
        }
        if (VpnService.prepare(this) == null) {
            ContextCompat.startForegroundService(
                this,
                Intent(this, SbEasyVpnService::class.java).setAction(SbEasyVpnService.ACTION_START),
            )
            qsTile?.state = Tile.STATE_ACTIVE
            qsTile?.updateTile()
        } else {
            openMainActivity()
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    @Suppress("DEPRECATION")
    private fun openMainActivity() {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(
                    this,
                    7,
                    intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ),
            )
        } else {
            startActivityAndCollapse(intent)
        }
    }

    private fun updateTile() {
        val connected = VpnRuntimeState.state.value.phase == VpnPhase.CONNECTED
        qsTile?.state = if (connected) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            qsTile?.subtitle = if (connected) "已连接" else "未连接"
        }
        qsTile?.updateTile()
    }
}
