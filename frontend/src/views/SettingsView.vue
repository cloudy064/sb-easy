<template>
  <div>
    <div class="page-header">
      <h2>{{ t('page.settings.title') }}</h2>
      <p class="text-sm text-muted" style="margin-top:0.25rem">
        Interface and firewall rules are managed internally. Configure sing-box connection and general preferences below.
      </p>
    </div>

    <div class="section-stack">
      <!-- WireGuard Interface (read-only — managed internally) -->
      <div class="card">
        <h3 class="section-title">WireGuard Interface</h3>
        <p class="text-sm text-muted mb-4">
          Interface lifecycle and iptables rules are handled internally by sb-easy.
          Set these via environment variables at startup.
        </p>
        <div class="settings-grid">
          <div class="form-group"><label>Interface</label><input :value="wg.interface" readonly style="opacity:0.55;cursor:default" /></div>
          <div class="form-group"><label>Listen Port</label><input :value="wg.listen_port" readonly style="opacity:0.55;cursor:default" /></div>
        </div>
        <div class="settings-grid">
          <div class="form-group"><label>Address (CIDR)</label><input :value="wg.address" readonly style="opacity:0.55;cursor:default" /></div>
          <div class="form-group"><label>MTU</label><input :value="wg.mtu" readonly style="opacity:0.55;cursor:default" /></div>
        </div>
        <p class="text-xs text-muted">
          To change these, edit <code>WG_INTERFACE</code>, <code>WG_PORT</code>, <code>WG_ADDRESS</code>,
          <code>WG_MTU</code> environment variables and restart.
        </p>
      </div>

      <!-- Sing-box Connection -->
      <div class="card">
        <h3 class="section-title">Sing-box Connection</h3>
        <p class="text-sm text-muted mb-4">Clash API endpoint for latency testing and status queries.</p>
        <div class="settings-grid">
          <div class="form-group"><label>Clash API URL</label><input v-model="sb.api_url" placeholder="http://10.168.1.5:9090" /></div>
          <div class="form-group"><label>API Secret</label><input v-model="sb.secret" type="password" placeholder="Optional" /></div>
        </div>
        <p class="text-xs text-muted">The sing-box instance must have <code>experimental.clash_api</code> enabled.</p>
      </div>

      <!-- General -->
      <div class="card">
        <h3 class="section-title">General</h3>
        <div class="settings-grid">
          <div class="form-group"><label>External Hostname</label><input v-model="general.external_hostname" placeholder="39.108.98.208" /></div>
          <div class="form-group"><label>One-Time Link Expiry (min)</label><input v-model.number="general.one_time_link_expiry_minutes" type="number" /></div>
        </div>
        <p class="text-xs text-muted">Hostname used as <code>Endpoint</code> in WireGuard client configs.</p>
      </div>

      <!-- Backup & Restore -->
      <div class="card">
        <h3 class="section-title">Backup &amp; Restore</h3>
        <p class="text-sm text-muted mb-4">
          Export all nodes, clients, subscriptions and settings as a JSON file, or restore from one.
          Restore upserts records and never deletes data the backup doesn't mention.
        </p>
        <div class="flex-center gap-3">
          <button class="btn-secondary btn-sm" @click="exportBackup">Export backup</button>
          <button class="btn-secondary btn-sm" @click="fileInput?.click()">Import backup…</button>
          <input ref="fileInput" type="file" accept="application/json" style="display:none" @change="importBackup" />
          <span v-if="restoreMsg" class="text-xs text-muted">{{ restoreMsg }}</span>
        </div>
      </div>

      <div style="display:flex;justify-content:flex-end">
        <button class="btn-primary" @click="saveSettings">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:0.4rem">
            <path d="M8 1l5 5v7H1V1h7z" stroke-linejoin="round"/><path d="M9 1v5h5"/>
          </svg>
          Save Settings
        </button>
      </div>
    </div>

    <div v-if="saved" class="toast"><div class="toast-item toast-success">Settings saved</div></div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
const { t } = useI18n()
import { ref, onMounted } from 'vue'
import client from '../api/client'

const wg = ref({ interface: '—', listen_port: 0, address: '—', mtu: 0 })
const sb = ref({ api_url: 'http://127.0.0.1:9090', secret: '' })
const general = ref({ external_hostname: '', one_time_link_expiry_minutes: 5 })
const saved = ref(false)
const fileInput = ref<HTMLInputElement | null>(null)
const restoreMsg = ref('')

onMounted(async () => {
  try {
    const { data } = await client.get('/settings')
    if (data.wireguard_interface) wg.value = { ...wg.value, ...data.wireguard_interface }
    if (data.singbox_connection) sb.value = { ...sb.value, ...data.singbox_connection }
    if (data.general) general.value = { ...general.value, ...data.general }
  } catch {}
})

async function saveSettings() {
  await client.put('/settings', {
    singbox_connection: sb.value,
    general: general.value,
  })
  saved.value = true
  setTimeout(() => (saved.value = false), 2200)
}

async function exportBackup() {
  const { data } = await client.get('/settings/backup')
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `sb-easy-backup-${new Date().toISOString().slice(0, 10)}.json`
  a.click()
  URL.revokeObjectURL(url)
}

async function importBackup(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    const text = await file.text()
    const payload = JSON.parse(text)
    const { data } = await client.post('/settings/restore', payload)
    const r = data.restored || {}
    restoreMsg.value = `Restored ${r.proxy_nodes || 0} nodes, ${r.subscriptions || 0} subscriptions, ${r.app_settings || 0} settings.`
  } catch (err) {
    restoreMsg.value = 'Import failed — invalid backup file.'
  } finally {
    input.value = ''
    setTimeout(() => (restoreMsg.value = ''), 5000)
  }
}
</script>

<style scoped>
.section-title { font-size: 0.95rem; font-weight: 650; margin-bottom: 0.25rem; }
.settings-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0 1.25rem; }
@media (max-width: 600px) { .settings-grid { grid-template-columns: 1fr; } }
</style>
