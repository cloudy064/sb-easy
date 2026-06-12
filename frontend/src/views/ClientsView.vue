<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>Clients</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">Manage VPN clients, download configs, and monitor connections.</p>
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
            <h3 class="peer-name">{{ peer.name }}</h3>
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
        </div>

        <div class="peer-actions" v-if="peer.enabled || peer.latest_handshake">
          <!-- stats renders even when disabled if there's history -->
        </div>

        <div class="peer-actions">
          <button class="btn-ghost btn-sm" @click="editPeer(peer)">Edit</button>
          <a :href="`/api/wireguard/peers/${peer.id}/config`" class="btn-ghost btn-sm" style="text-decoration:none;display:inline-flex;align-items:center">Download .conf</a>
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
    <div v-if="qrPeer" class="modal-overlay" @click.self="qrPeer = null">
      <div class="modal" style="text-align:center">
        <h3>QR Code &mdash; {{ qrPeer.name }}</h3>
        <img :src="`/api/wireguard/peers/${qrPeer.id}/qr`" alt="QR Code" style="max-width:280px;margin:1rem auto;display:block" />
        <button class="btn-secondary btn-sm" @click="qrPeer = null">Close</button>
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
import { ref, onMounted } from 'vue'
import { useWireGuardStore } from '../stores/wireguard'
import type { WireGuardPeer } from '../types'
import client from '../api/client'

const store = useWireGuardStore()
const showCreate = ref(false)
const editTarget = ref<WireGuardPeer | null>(null)
const deleteTarget = ref<WireGuardPeer | null>(null)
const qrPeer = ref<WireGuardPeer | null>(null)

const form = ref({ name: '', address: '', dns: '10.59.32.1', persistent_keepalive: 25 })
const editForm = ref({ name: '', dns: '', persistent_keepalive: 25, allowed_ips: '', notes: '' })

onMounted(() => store.fetchPeers())

async function doCreate() {
  await store.createPeer({
    ...form.value,
    address: form.value.address || undefined,
  })
  showCreate.value = false
  form.value = { name: '', address: '', dns: '10.59.32.1', persistent_keepalive: 25 }
}

function editPeer(peer: WireGuardPeer) {
  editTarget.value = peer
  editForm.value = {
    name: peer.name, dns: peer.dns,
    persistent_keepalive: peer.persistent_keepalive,
    allowed_ips: peer.allowed_ips, notes: peer.notes || '',
  }
}

async function doUpdate() {
  if (!editTarget.value) return
  await store.updatePeer(editTarget.value.id, editForm.value)
  editTarget.value = null
}

function confirmDelete(peer: WireGuardPeer) { deleteTarget.value = peer }
async function doDelete() {
  if (!deleteTarget.value) return
  await store.deletePeer(deleteTarget.value.id)
  deleteTarget.value = null
}

function showQr(peer: WireGuardPeer) { qrPeer.value = peer }

async function syncConfig() {
  await client.post('/wireguard/sync')
  await store.fetchPeers()
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
  background: #faf8f4;
  border-radius: var(--radius-sm);
  border: 1px solid #f0ece5;
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
</style>
