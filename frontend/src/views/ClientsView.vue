<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.clients.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.clients.desc') }}</p>
      </div>
      <div class="flex-center gap-3">
        <button class="btn-secondary btn-sm" @click="syncConfig">Sync Config</button>
        <button class="btn-primary" @click="showCreate = true">Add Client</button>
      </div>
    </div>

    <div v-if="store.loading" class="loading-center"><div class="spinner"></div></div>

    <div
      v-else-if="store.peers.length === 0"
      class="empty-state"
    >
      <span class="empty-icon">+</span>
      <p>No clients configured yet. Create your first client to begin building your private network.</p>
    </div>

    <div v-else class="grid-2">
      <article v-for="peer in store.peers" :key="peer.id" class="card peer-card">
        <div class="peer-card-top">
          <div class="peer-info">
            <h3 class="peer-name">
              <span class="online-dot" :class="isOnline(peer) ? 'on' : 'off'" :title="isOnline(peer) ? 'Online' : 'Offline'"></span>
              {{ peer.name }}
              <span class="kind-badge" :class="peer.kind === 'agent' ? 'kind-agent' : 'kind-wg'"
                    :title="peer.kind === 'agent' ? 'Managed sb-easy agent' : 'Plain WireGuard client'">
                {{ peer.kind === 'agent' ? 'AGENT' : 'WG' }}
              </span>
              <span v-if="peer.expired" class="badge badge-red" style="margin-left:0.4rem">Expired</span>
            </h3>
            <span class="peer-addr">{{ peer.address }}</span>
          </div>
          <label class="toggle">
            <input type="checkbox" :checked="peer.enabled" @change="store.togglePeer(peer.id, !peer.enabled)" />
            <span class="slider"></span>
          </label>
        </div>

        <div class="peer-stats">
          <div class="peer-stat" v-if="peer.endpoint">
            <span class="peer-stat-label">Endpoint</span>
            <span class="peer-stat-value text-sm truncate" style="max-width:180px">{{ peer.endpoint }}</span>
          </div>
          <div class="peer-stat" v-if="peer.latest_handshake">
            <span class="peer-stat-label">Last Handshake</span>
            <span class="peer-stat-value text-sm">{{ formatTime(peer.latest_handshake) }}</span>
          </div>
          <div class="peer-stat" v-if="peer.transfer_rx !== undefined">
            <span class="peer-stat-label">Transfer</span>
            <span class="peer-stat-value text-sm">
              <span style="color:var(--ok)">↓ {{ formatBytes(peer.transfer_rx) }}</span>
              <span style="margin-left:0.5rem;color:var(--info)">↑ {{ formatBytes(peer.transfer_tx || 0) }}</span>
            </span>
          </div>
          <div class="peer-stat" v-if="peer.expire_at">
            <span class="peer-stat-label">Expires</span>
            <span class="peer-stat-value text-sm">{{ peer.expire_at }}</span>
          </div>
          <div class="peer-stat" v-if="peer.quota_bytes && peer.quota_bytes > 0" style="grid-column:1/-1">
            <span class="peer-stat-label">Quota</span>
            <span class="peer-stat-value text-sm">{{ formatBytes(usedBytes(peer)) }} / {{ formatBytes(peer.quota_bytes) }}</span>
            <div class="quota-bar"><div class="quota-fill" :class="quotaClass(peer)" :style="{ width: quotaPct(peer) + '%' }"></div></div>
          </div>
        </div>

        <div class="peer-actions" v-if="peer.enabled || peer.latest_handshake">
          <!-- stats renders even when disabled if there's history -->
        </div>

        <div class="peer-actions">
          <button class="btn-ghost btn-sm" @click="editPeer(peer)">Edit</button>
          <button class="btn-ghost btn-sm" @click="store.downloadConfig(peer.id)">Download .conf</button>
          <button class="btn-ghost btn-sm" @click="showQr(peer)">QR Code</button>
          <button class="btn-danger btn-sm" @click="confirmDelete(peer)">Delete</button>
        </div>
      </article>
    </div>

    <!-- Create Dialog -->
    <div v-if="showCreate" class="modal-overlay" @click.self="showCreate = false">
      <div class="modal">
        <h3>Add Client</h3>
        <form @submit.prevent="doCreate">
          <div class="form-group"><label>Name</label><input v-model="form.name" required placeholder="e.g. office-pc" /></div>
          <div class="form-group"><label>Address</label><input v-model="form.address" placeholder="Auto-assign if left empty (10.59.32.x/24)" /></div>
          <div class="form-group"><label>DNS Server</label><input v-model="form.dns" placeholder="10.59.32.1" /></div>
          <div class="form-group"><label>Persistent Keepalive (seconds)</label><input v-model.number="form.persistent_keepalive" type="number" /></div>
          <div class="form-group"><label>Traffic Quota (GB, 0 = unlimited)</label><input v-model.number="form.quota_gb" type="number" min="0" step="0.5" /></div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showCreate = false">Cancel</button>
            <button type="submit" class="btn-primary">Add Client</button>
          </div>
        </form>
      </div>
    </div>

    <!-- Edit Dialog -->
    <div v-if="editTarget" class="modal-overlay" @click.self="editTarget = null">
      <div class="modal">
        <h3>Edit &ldquo;{{ editTarget.name }}&rdquo;</h3>
        <form @submit.prevent="doUpdate">
          <div class="form-group"><label>Name</label><input v-model="editForm.name" required /></div>
          <div class="form-group"><label>DNS</label><input v-model="editForm.dns" /></div>
          <div class="form-group"><label>Keepalive</label><input v-model.number="editForm.persistent_keepalive" type="number" /></div>
          <div class="form-group"><label>Traffic Quota (GB, 0 = unlimited)</label><input v-model.number="editForm.quota_gb" type="number" min="0" step="0.5" /></div>
          <div class="form-group"><label>Allowed IPs</label><input v-model="editForm.allowed_ips" /></div>
          <div class="form-group"><label>Notes</label><input v-model="editForm.notes" /></div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="editTarget = null">Cancel</button>
            <button type="submit" class="btn-primary">Save Changes</button>
          </div>
        </form>
      </div>
    </div>

    <!-- QR Dialog -->
    <div v-if="qrPeer" class="modal-overlay" @click.self="closeQr">
      <div class="modal" style="text-align:center">
        <h3>QR Code &mdash; {{ qrPeer.name }}</h3>
        <img v-if="qrSrc" :src="qrSrc" alt="QR Code" style="max-width:280px;margin:1rem auto;display:block" />
        <div v-else class="spinner" style="margin:2rem auto"></div>
        <button class="btn-secondary btn-sm" @click="closeQr">Close</button>
      </div>
    </div>

    <!-- Delete Confirm -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal">
        <h3>Delete &ldquo;{{ deleteTarget.name }}&rdquo;?</h3>
        <p class="text-sm text-muted">This will permanently remove the client. It will no longer be able to connect to your VPN.</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="deleteTarget = null">Cancel</button>
          <button class="btn-danger" @click="doDelete">Delete Peer</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
const { t } = useI18n()
import { ref, onMounted } from 'vue'
import { useWireGuardStore } from '../stores/wireguard'
import type { WireGuardPeer } from '../types'
import client from '../api/client'

const store = useWireGuardStore()
const showCreate = ref(false)
const editTarget = ref<WireGuardPeer | null>(null)
const deleteTarget = ref<WireGuardPeer | null>(null)
const qrPeer = ref<WireGuardPeer | null>(null)
const qrSrc = ref('')

const GB = 1024 * 1024 * 1024
const form = ref({ name: '', address: '', dns: '10.59.32.1', persistent_keepalive: 25, quota_gb: 0 })
const editForm = ref({ name: '', dns: '', persistent_keepalive: 25, quota_gb: 0, allowed_ips: '', notes: '' })

onMounted(() => store.fetchPeers())

async function doCreate() {
  const { quota_gb, ...rest } = form.value
  await store.createPeer({
    ...rest,
    address: form.value.address || undefined,
    quota_bytes: Math.round((quota_gb || 0) * GB),
  })
  showCreate.value = false
  form.value = { name: '', address: '', dns: '10.59.32.1', persistent_keepalive: 25, quota_gb: 0 }
}

function editPeer(peer: WireGuardPeer) {
  editTarget.value = peer
  editForm.value = {
    name: peer.name, dns: peer.dns,
    persistent_keepalive: peer.persistent_keepalive,
    quota_gb: peer.quota_bytes ? +(peer.quota_bytes / GB).toFixed(2) : 0,
    allowed_ips: peer.allowed_ips, notes: peer.notes || '',
  }
}

async function doUpdate() {
  if (!editTarget.value) return
  const { quota_gb, ...rest } = editForm.value
  await store.updatePeer(editTarget.value.id, {
    ...rest,
    quota_bytes: Math.round((quota_gb || 0) * GB),
  })
  editTarget.value = null
}

function usedBytes(peer: WireGuardPeer) {
  return (peer.transfer_rx || 0) + (peer.transfer_tx || 0)
}
function quotaPct(peer: WireGuardPeer) {
  if (!peer.quota_bytes) return 0
  return Math.min(100, (usedBytes(peer) / peer.quota_bytes) * 100)
}
function quotaClass(peer: WireGuardPeer) {
  const p = quotaPct(peer)
  if (p >= 100) return 'q-bad'
  if (p >= 80) return 'q-warn'
  return 'q-ok'
}

function confirmDelete(peer: WireGuardPeer) { deleteTarget.value = peer }
async function doDelete() {
  if (!deleteTarget.value) return
  await store.deletePeer(deleteTarget.value.id)
  deleteTarget.value = null
}

function showQr(peer: WireGuardPeer) {
  qrPeer.value = peer
  qrSrc.value = ''
  store.fetchQR(peer.id).then(url => { qrSrc.value = url })
}
function closeQr() {
  if (qrSrc.value) { window.URL.revokeObjectURL(qrSrc.value); qrSrc.value = '' }
  qrPeer.value = null
}

async function syncConfig() {
  await client.post('/wireguard/sync')
  await store.fetchPeers()
}

function isOnline(peer: WireGuardPeer) {
  // A handshake within the last 3 minutes means the tunnel is live.
  if (!peer.latest_handshake) return false
  return Date.now() / 1000 - peer.latest_handshake < 180
}

function formatTime(ts: number) {
  return new Date(ts * 1000).toLocaleString()
}

function formatBytes(b: number) {
  if (b < 1024) return b + ' B'
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB'
  return (b / 1073741824).toFixed(2) + ' GB'
}
</script>

<style scoped>
.peer-card {
  padding: 1.75rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.peer-card-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.peer-name {
  font-size: 0.95rem;
  font-weight: 650;
  color: var(--ink-primary);
}
.kind-badge {
  font-family: var(--font-mono);
  font-size: 0.58rem; font-weight: 700; letter-spacing: 0.05em;
  padding: 0.12rem 0.4rem; border-radius: 4px; margin-left: 0.4rem; vertical-align: middle;
}
.kind-agent { background: var(--accent-subtle); color: var(--accent); }
.kind-wg { background: #e8f0fe; color: #3c6ea8; }
.online-dot {
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
  margin-right: 0.35rem;
  vertical-align: middle;
}
.online-dot.on  { background: var(--ok); box-shadow: 0 0 0 3px var(--ok-bg); }
.online-dot.off { background: #cbc4b8; }

.peer-addr {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  color: var(--ink-muted);
  margin-top: 0.15rem;
  display: block;
}

.peer-stats {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 0.75rem;
  padding: 0.75rem;
  background: var(--paper-bg);
  border-radius: var(--radius-sm);
  border: 1px solid var(--paper-border);
  box-shadow: inset 0 1px 3px rgba(0,0,0,.04);
}

.peer-stat {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
}

.peer-stat-label {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--ink-muted);
}

.peer-actions {
  display: flex;
  gap: 0.3rem;
  flex-wrap: wrap;
}

.quota-bar {
  width: 100%;
  height: 5px;
  background: var(--paper-border);
  border-radius: 3px;
  margin-top: 0.3rem;
  overflow: hidden;
}
.quota-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
.q-ok   { background: var(--ok); }
.q-warn { background: var(--warn); }
.q-bad  { background: var(--bad); }
</style>
