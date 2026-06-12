<template>
  <div>
    <div class="page-header">
      <h2>Settings</h2>
      <p class="text-sm text-muted" style="margin-top:0.25rem">Configure WireGuard interface, sing-box connection, and general preferences.</p>
    </div>

    <div class="section-stack">
      <!-- WireGuard Interface -->
      <div class="card">
        <h3 class="section-title">WireGuard Interface</h3>
        <p class="text-sm text-muted mb-4">Settings for the WireGuard kernel interface running on this server.</p>
        <div class="settings-grid">
          <div class="form-group"><label>Interface Name</label><input v-model="wg.interface" readonly style="opacity:0.55;background:#faf8f4;cursor:default" /></div>
          <div class="form-group"><label>Listen Port</label><input v-model.number="wg.listen_port" type="number" /></div>
        </div>
        <div class="form-group"><label>Server Address (CIDR)</label><input v-model="wg.address" placeholder="10.59.32.1/24" /></div>
        <div class="settings-grid">
          <div class="form-group"><label>DNS</label><input v-model="wg.dns" /></div>
          <div class="form-group"><label>MTU</label><input v-model.number="wg.mtu" type="number" /></div>
        </div>
        <div class="form-group"><label>Post-Up Script</label><textarea v-model="wg.post_up" rows="2" class="font-mono" placeholder="iptables rules..."></textarea></div>
        <div class="form-group"><label>Post-Down Script</label><textarea v-model="wg.post_down" rows="2" class="font-mono" placeholder="iptables rules..."></textarea></div>
      </div>

      <!-- Sing-box Connection -->
      <div class="card">
        <h3 class="section-title">Sing-box Connection</h3>
        <p class="text-sm text-muted mb-4">Connection details for the sing-box instance&rsquo;s Clash API. Used for latency testing and status queries.</p>
        <div class="settings-grid">
          <div class="form-group"><label>Clash API URL</label><input v-model="sb.api_url" placeholder="http://10.168.1.5:9090" /></div>
          <div class="form-group"><label>API Secret</label><input v-model="sb.secret" type="password" placeholder="Optional" /></div>
        </div>
        <p class="text-xs text-muted">The sing-box instance must have <code>experimental.clash_api</code> enabled in its configuration.</p>
      </div>

      <!-- General -->
      <div class="card">
        <h3 class="section-title">General</h3>
        <p class="text-sm text-muted mb-4">Application-wide preferences.</p>
        <div class="settings-grid">
          <div class="form-group"><label>External Hostname</label><input v-model="general.external_hostname" placeholder="39.108.98.208" /></div>
          <div class="form-group"><label>One-Time Link Expiry (minutes)</label><input v-model.number="general.one_time_link_expiry_minutes" type="number" /></div>
        </div>
        <p class="text-xs text-muted">The external hostname is used in WireGuard client configs as the <code>Endpoint</code> address.</p>
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
import { ref, onMounted } from 'vue'
import client from '../api/client'

const wg = ref({
  interface: 'wg0', listen_port: 51820,
  address: '10.59.32.1/24', dns: '10.59.32.1',
  mtu: 1420, post_up: '', post_down: '',
})
const sb = ref({ api_url: 'http://10.168.1.5:9090', secret: '' })
const general = ref({
  app_name: 'sb-easy',
  external_hostname: '39.108.98.208',
  one_time_link_expiry_minutes: 5,
})
const saved = ref(false)

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
    wireguard_interface: wg.value,
    singbox_connection: sb.value,
    general: general.value,
  })
  saved.value = true
  setTimeout(() => (saved.value = false), 2200)
}
</script>

<style scoped>
.section-title {
  font-size: 0.95rem;
  font-weight: 650;
  margin-bottom: 0.25rem;
}

.settings-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 1.25rem;
}
@media (max-width: 600px) {
  .settings-grid { grid-template-columns: 1fr; }
}
</style>
