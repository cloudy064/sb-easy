<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.devices.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.devices.desc') }}</p>
      </div>
      <div class="flex-center gap-3">
        <button class="btn-secondary btn-sm" @click="syncConfig">Sync Config</button>
        <button class="btn-secondary btn-sm" @click="openManage(null)">{{ t('devices.add.host') }}</button>
        <button class="btn-secondary btn-sm" @click="openAndroid">{{ t('devices.add.android') }}</button>
        <button class="btn-primary" @click="showCreate = true">{{ t('devices.add.client') }}</button>
      </div>
    </div>

    <!-- Two orthogonal facets: Type × Status (combined with AND) -->
    <div class="filters mb-5">
      <div class="filter-row">
        <span class="filter-label">{{ t('devices.filter.type') }}</span>
        <div class="seg">
          <button class="seg-btn" :class="{ active: typeFilter === 'all' }" @click="typeFilter = 'all'">{{ t('devices.filter.all') }}<span class="seg-count">{{ typeCounts.all }}</span></button>
          <button class="seg-btn" :class="{ active: typeFilter === 'hosts' }" @click="typeFilter = 'hosts'">{{ t('devices.filter.hosts') }}<span class="seg-count">{{ typeCounts.hosts }}</span></button>
          <button class="seg-btn" :class="{ active: typeFilter === 'clients' }" @click="typeFilter = 'clients'">{{ t('devices.filter.clients') }}<span class="seg-count">{{ typeCounts.clients }}</span></button>
        </div>
      </div>
      <div class="filter-row">
        <span class="filter-label">{{ t('devices.filter.status') }}</span>
        <div class="seg">
          <button class="seg-btn" :class="{ active: statusFilter === 'all' }" @click="statusFilter = 'all'">{{ t('devices.filter.all') }}<span class="seg-count">{{ statusCounts.all }}</span></button>
          <button class="seg-btn" :class="{ active: statusFilter === 'online' }" @click="statusFilter = 'online'">{{ t('devices.filter.online') }}<span class="seg-count">{{ statusCounts.online }}</span></button>
          <button class="seg-btn" :class="{ active: statusFilter === 'offline' }" @click="statusFilter = 'offline'">{{ t('devices.filter.offline') }}<span class="seg-count">{{ statusCounts.offline }}</span></button>
        </div>
      </div>
    </div>

    <div v-if="loading" class="loading-center"><div class="spinner"></div></div>

    <div v-else-if="devices.length === 0" class="empty-state">
      <span class="empty-icon">+</span>
      <p>{{ t('devices.empty') }}</p>
    </div>

    <div v-else class="device-grid">
      <article v-for="d in devices" :key="d._t + ':' + d.id" class="card device-card">
        <!-- Header -->
        <div class="device-top">
          <div class="device-info">
            <h3 class="device-name">
              <span class="online-dot" :class="online(d) ? 'on' : 'off'" :title="online(d) ? 'Online' : 'Offline'"></span>
              <router-link v-if="d._t === 'host'" :to="`/devices/${d.id}`" class="device-name-link">{{ d.name }}</router-link>
              <template v-else>{{ d.name }}</template>
              <span class="type-badge" :class="d._t === 'host' ? 'type-host' : 'type-client'">
                {{ d._t === 'host' ? t('devices.type.host') : t('devices.type.client') }}
              </span>
              <!-- client sub-kind -->
              <template v-if="d._t === 'client'">
                <span class="kind-badge" :class="d.kind === 'agent' ? 'kind-agent' : 'kind-wg'">
                  {{ d.kind === 'agent' ? 'AGENT' : 'WG' }}
                </span>
                <span v-if="d.expired" class="badge badge-red" style="margin-left:0.4rem">Expired</span>
              </template>
              <!-- host sub-state -->
              <template v-else>
                <span v-if="d.is_self" class="kind-badge kind-self">SELF</span>
                <span v-if="d.capabilities?.platform === 'android'" class="kind-badge kind-android">ANDROID</span>
                <span v-if="d.config_drift" class="badge badge-red" style="margin-left:0.4rem" :title="t('hosts.drift.hint')">{{ t('hosts.drift') }}</span>
              </template>
            </h3>
            <span class="device-addr">{{ d.address || '—' }}</span>
          </div>
          <label class="toggle">
            <input type="checkbox" :checked="d.enabled" @change="toggle(d)" />
            <span class="slider"></span>
          </label>
        </div>

        <!-- Stats -->
        <div class="device-stats">
          <!-- CLIENT stats -->
          <template v-if="d._t === 'client'">
            <div class="device-stat">
              <span class="device-stat-label">Endpoint</span>
              <span class="device-stat-value text-sm truncate" style="max-width:180px">{{ d.endpoint || '—' }}</span>
            </div>
            <div class="device-stat">
              <span class="device-stat-label">Last Handshake</span>
              <span class="device-stat-value text-sm">{{ d.latest_handshake ? formatTime(d.latest_handshake) : '—' }}</span>
            </div>
            <div class="device-stat">
              <span class="device-stat-label">Transfer</span>
              <span class="device-stat-value text-sm">
                <span style="color:var(--ok)">↓ {{ formatBytes(d.transfer_rx ?? 0) }}</span>
                <span style="margin-left:0.5rem;color:var(--info)">↑ {{ formatBytes(d.transfer_tx || 0) }}</span>
              </span>
            </div>
            <div class="device-stat" v-if="d.quota_bytes && d.quota_bytes > 0" style="grid-column:1/-1">
              <span class="device-stat-label">Quota</span>
              <span class="device-stat-value text-sm">{{ formatBytes(usedBytes(d)) }} / {{ formatBytes(d.quota_bytes) }}</span>
              <div class="quota-bar"><div class="quota-fill" :class="quotaClass(d)" :style="{ width: quotaPct(d) + '%' }"></div></div>
            </div>
          </template>
          <!-- HOST stats -->
          <template v-else>
            <div class="device-stat">
              <span class="device-stat-label">Clash API</span>
              <span class="device-stat-value text-sm truncate" style="max-width:180px">{{ d.clash_api || '—' }}</span>
            </div>
            <div class="device-stat">
              <span class="device-stat-label">Status</span>
              <span class="device-stat-value text-sm">{{ hostStatus(d) }}</span>
            </div>
            <div class="device-stat">
              <span class="device-stat-label">sing-box</span>
              <span class="device-stat-value text-sm" :title="d.singbox_state || ''">{{ singboxState(d) || '—' }}</span>
            </div>
            <div class="device-stat">
              <span class="device-stat-label">{{ t('devices.host.proxies') }}</span>
              <span class="device-stat-value text-sm">{{ d.assigned_outbounds ? d.assigned_outbounds + ' ' + t('devices.host.proxies.n') : t('devices.host.proxies.all') }}</span>
            </div>
            <!-- WG membership of this host (its auto-provisioned host-peer), folded in
                 so the machine shows as a single card instead of host + duplicate client. -->
            <template v-if="d.wg">
              <div class="device-stat">
                <span class="device-stat-label">WG Handshake</span>
                <span class="device-stat-value text-sm">{{ d.wg.latest_handshake ? formatTime(d.wg.latest_handshake) : '—' }}</span>
              </div>
              <div class="device-stat">
                <span class="device-stat-label">WG Transfer</span>
                <span class="device-stat-value text-sm">
                  <span style="color:var(--ok)">↓ {{ formatBytes(d.wg.transfer_rx ?? 0) }}</span>
                  <span style="margin-left:0.5rem;color:var(--info)">↑ {{ formatBytes(d.wg.transfer_tx || 0) }}</span>
                </span>
              </div>
            </template>
          </template>
        </div>

        <!-- Actions -->
        <div class="device-actions">
          <template v-if="d._t === 'client'">
            <button class="btn-ghost btn-sm" @click="editClient(d)">Edit</button>
            <button class="btn-ghost btn-sm" @click="wgStore.downloadConfig(d.id)">Download .conf</button>
            <button class="btn-ghost btn-sm" @click="showQr(d)">QR Code</button>
            <button class="btn-danger btn-sm" @click="deleteTarget = d">Delete</button>
          </template>
          <template v-else>
            <button class="btn-ghost btn-sm" :disabled="d.is_self" @click="cmd(d, 'reload')">{{ t('hosts.reload') }}</button>
            <button class="btn-ghost btn-sm" :disabled="d.is_self" @click="cmd(d, 'restart')">{{ t('hosts.restart') }}</button>
            <button class="btn-ghost btn-sm" @click="openManage(d)">{{ t('hosts.edit') }}</button>
            <button class="btn-danger btn-sm" :disabled="d.is_self" @click="deleteTarget = d">Delete</button>
          </template>
        </div>
      </article>
    </div>

    <!-- Create client -->
    <div v-if="showCreate" class="modal-overlay" @click.self="showCreate = false">
      <div class="modal">
        <h3>{{ t('devices.add.client') }}</h3>
        <form @submit.prevent="doCreateClient">
          <div class="form-group"><label>Name</label><input v-model="form.name" required placeholder="e.g. office-pc" /></div>
          <div class="form-group"><label>Address</label><input v-model="form.address" placeholder="Auto-assign if left empty (10.59.32.x/24)" /></div>
          <div class="form-group"><label>DNS Server</label><input v-model="form.dns" placeholder="10.59.32.1" /></div>
          <div class="form-group"><label>Persistent Keepalive (seconds)</label><input v-model.number="form.persistent_keepalive" type="number" /></div>
          <div class="form-group"><label>Traffic Quota (GB, 0 = unlimited)</label><input v-model.number="form.quota_gb" type="number" min="0" step="0.5" /></div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showCreate = false">Cancel</button>
            <button type="submit" class="btn-primary">{{ t('devices.add.client') }}</button>
          </div>
        </form>
      </div>
    </div>

    <!-- Android enrollment -->
    <div v-if="showAndroid" class="modal-overlay" @click.self="closeAndroid">
      <div class="modal android-modal">
        <template v-if="!androidEnrollment">
          <h3>{{ t('android.enroll.title') }}</h3>
          <p class="text-sm text-muted android-lead">{{ t('android.enroll.hint') }}</p>
          <form @submit.prevent="createAndroidEnrollment">
            <div class="form-group">
              <label>{{ t('android.enroll.name') }}</label>
              <input v-model.trim="androidName" required :placeholder="t('android.enroll.name.placeholder')" />
            </div>
            <div class="modal-actions">
              <button type="button" class="btn-secondary" @click="closeAndroid">{{ t('action.cancel') }}</button>
              <button type="submit" class="btn-primary" :disabled="androidCreating">
                {{ androidCreating ? t('android.enroll.creating') : t('android.enroll.create') }}
              </button>
            </div>
          </form>
        </template>
        <template v-else>
          <h3>{{ t('android.enroll.ready') }}</h3>
          <p class="text-sm text-muted android-lead">{{ t('android.enroll.scan') }}</p>
          <div class="android-enrollment-layout">
            <img :src="androidQrSrc" :alt="t('android.enroll.qr.alt')" class="android-qr" />
            <div class="android-enrollment-info">
              <div class="enrollment-meta">
                <span>{{ t('android.enroll.server') }}</span>
                <strong>{{ androidEnrollment.server }}</strong>
              </div>
              <div class="enrollment-meta">
                <span>{{ t('android.enroll.expires') }}</span>
                <strong>{{ enrollmentExpiry(androidEnrollment.expires_at) }}</strong>
              </div>
              <label class="text-sm">{{ t('android.enroll.manual') }}</label>
              <textarea readonly rows="4" :value="androidEnrollment.enrollment_uri"></textarea>
              <button class="btn-secondary btn-sm" @click="copyEnrollment">{{ t('action.copy') }}</button>
            </div>
          </div>
          <div class="modal-actions">
            <button class="btn-secondary" @click="closeAndroid">{{ t('action.close') }}</button>
            <button class="btn-primary" @click="resetAndroid">{{ t('android.enroll.another') }}</button>
          </div>
        </template>
      </div>
    </div>

    <!-- Edit client -->
    <div v-if="editTarget" class="modal-overlay" @click.self="editTarget = null">
      <div class="modal">
        <h3>Edit &ldquo;{{ editTarget.name }}&rdquo;</h3>
        <form @submit.prevent="doUpdateClient">
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

    <!-- QR -->
    <div v-if="qrPeer" class="modal-overlay" @click.self="closeQr">
      <div class="modal" style="text-align:center">
        <h3>QR Code &mdash; {{ qrPeer.name }}</h3>
        <img v-if="qrSrc" :src="qrSrc" alt="QR Code" style="max-width:280px;margin:1rem auto;display:block" />
        <div v-else class="spinner" style="margin:2rem auto"></div>
        <button class="btn-secondary btn-sm" @click="closeQr">Close</button>
      </div>
    </div>

    <!-- Delete confirm -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal">
        <h3>Delete &ldquo;{{ deleteTarget.name }}&rdquo;?</h3>
        <p class="text-sm text-muted">
          {{ deleteTarget._t === 'host' ? t('hosts.delete.hint') : 'This will permanently remove the client. It will no longer be able to connect.' }}
        </p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="deleteTarget = null">Cancel</button>
          <button class="btn-danger" @click="doDelete">Delete</button>
        </div>
      </div>
    </div>

    <!-- Host create / manage -->
    <HostManageModal v-if="showManage" :host="manageHost" @close="showManage = false" @saved="onManageSaved" />

    <div v-if="toast" class="toast"><div class="toast-item" :class="toastClass">{{ toast }}</div></div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useI18n } from '../composables/i18n'
import { useHostsStore } from '../stores/hosts'
import { useWireGuardStore } from '../stores/wireguard'
import HostManageModal from '../components/HostManageModal.vue'
import client from '../api/client'
import { serverTimestampAgeMs } from '../api/time'
import type { AgentEnrollment, Host, WireGuardPeer } from '../types'

const { t } = useI18n()
const hostsStore = useHostsStore()
const wgStore = useWireGuardStore()

// Host create/manage modal (folds in everything the old /hosts page did).
const showManage = ref(false)
const manageHost = ref<Host | null>(null)
function openManage(d: HostRow | null) {
  manageHost.value = d // HostRow extends Host; null = create
  showManage.value = true
}
async function onManageSaved() {
  showManage.value = false
  await hostsStore.fetchHosts()
}

// Short, friendly sing-box state from the agent's reported JSON (running + version),
// instead of dumping the raw state blob (which includes the config etag).
function singboxState(d: HostRow): string {
  if (!d.singbox_state) return ''
  try {
    const st = JSON.parse(d.singbox_state)
    const dot = st.running === true ? '● running' : st.running === false ? '○ stopped' : ''
    return [dot, st.version].filter(Boolean).join(' ')
  } catch {
    return ''
  }
}

// Unified row shapes. `_t` is the discriminant — note WireGuardPeer already has
// its own `kind` ('agent' | 'wg') which we reuse for the sub-badge, so the
// discriminant must be a distinct name to avoid collapsing the union to never.
type ClientRow = WireGuardPeer & { _t: 'client' }
type HostRow = Host & { _t: 'host'; address: string | null; is_self: boolean; wg: WireGuardPeer | null }
type DeviceRow = ClientRow | HostRow

const typeFilter = ref<'all' | 'hosts' | 'clients'>('all')
const statusFilter = ref<'all' | 'online' | 'offline'>('all')
const loading = ref(false)
const showCreate = ref(false)
const showAndroid = ref(false)
const androidName = ref('')
const androidCreating = ref(false)
const androidEnrollment = ref<AgentEnrollment | null>(null)
const androidHostId = ref<string | null>(null)
const editTarget = ref<WireGuardPeer | null>(null)
const deleteTarget = ref<DeviceRow | null>(null)
const qrPeer = ref<WireGuardPeer | null>(null)
const qrSrc = ref('')

const androidQrSrc = computed(() => androidEnrollment.value
  ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(androidEnrollment.value.qr_svg)}`
  : '')

function openAndroid() {
  androidName.value = ''
  androidEnrollment.value = null
  androidHostId.value = null
  showAndroid.value = true
}
function closeAndroid() {
  showAndroid.value = false
  androidEnrollment.value = null
  androidName.value = ''
  androidHostId.value = null
}
function resetAndroid() {
  androidEnrollment.value = null
  androidName.value = ''
  androidHostId.value = null
}
async function createAndroidEnrollment() {
  if (!androidName.value || androidCreating.value) return
  androidCreating.value = true
  try {
    if (!androidHostId.value) {
      const host = await hostsStore.createHost({
        name: androidName.value,
        profile_id: 'android-client',
        capabilities: {
          runs_singbox: true,
          is_wg_member: false,
          is_wg_hub: false,
          is_self: false,
          platform: 'android',
        },
      })
      androidHostId.value = host.id
    }
    androidEnrollment.value = await hostsStore.createEnrollment(androidHostId.value)
  } catch (error) {
    notify(error instanceof Error ? error.message : t('android.enroll.failed'), false)
  } finally {
    androidCreating.value = false
  }
}
async function copyEnrollment() {
  if (!androidEnrollment.value) return
  await navigator.clipboard.writeText(androidEnrollment.value.enrollment_uri)
  notify(t('action.copied'))
}

function showQr(d: WireGuardPeer) {
  qrPeer.value = d
  qrSrc.value = ''
  wgStore.fetchQR(d.id).then(url => { qrSrc.value = url })
}
function closeQr() {
  if (qrSrc.value) { window.URL.revokeObjectURL(qrSrc.value); qrSrc.value = '' }
  qrPeer.value = null
}
const toast = ref('')
const toastClass = ref('toast-success')

const GB = 1024 * 1024 * 1024
const form = ref({ name: '', address: '', dns: '10.59.32.1', persistent_keepalive: 25, quota_gb: 0 })
const editForm = ref({ name: '', dns: '', persistent_keepalive: 25, quota_gb: 0, allowed_ips: '', notes: '' })

function notify(msg: string, ok = true) {
  toast.value = msg
  toastClass.value = ok ? 'toast-success' : 'toast-error'
  setTimeout(() => (toast.value = ''), 2200)
}

// Host-peers (a managed host's auto-provisioned WG membership) carry a host_id and
// are tagged kind:'agent' by the backend. Such a peer is the SAME machine as its
// Host card, so we drop it from the client list and instead fold its live WG stats
// into the matching Host card below — one card per real device, no duplicates.
const clientRows = computed<ClientRow[]>(() =>
  wgStore.peers
    .filter((p) => p.kind !== 'agent')
    .map((p) => ({ ...p, _t: 'client' as const })),
)
const hostPeerByHostId = computed<Record<string, WireGuardPeer>>(() => {
  const m: Record<string, WireGuardPeer> = {}
  for (const p of wgStore.peers) {
    if (p.kind === 'agent' && p.host_id) m[p.host_id] = p
  }
  return m
})
const hostRows = computed<HostRow[]>(() =>
  hostsStore.hosts.map((h) => ({
    ...h,
    _t: 'host' as const,
    address: h.wg_address,
    is_self: !!h.capabilities?.is_self,
    wg: hostPeerByHostId.value[h.id] ?? null,
  })),
)

// Two orthogonal facets, combined with AND: Type (all/hosts/clients) × Status
// (all/online/offline). Each facet's counts reflect the OTHER facet's selection.
function byStatus(list: DeviceRow[]): DeviceRow[] {
  if (statusFilter.value === 'online') return list.filter((d) => online(d))
  if (statusFilter.value === 'offline') return list.filter((d) => !online(d))
  return list
}
function byType(): DeviceRow[] {
  if (typeFilter.value === 'hosts') return hostRows.value
  if (typeFilter.value === 'clients') return clientRows.value
  return [...hostRows.value, ...clientRows.value]
}

const devices = computed<DeviceRow[]>(() => byStatus(byType()))

const typeCounts = computed(() => {
  const h = byStatus(hostRows.value)
  const c = byStatus(clientRows.value)
  return { all: h.length + c.length, hosts: h.length, clients: c.length }
})
const statusCounts = computed(() => {
  const base = byType()
  const on = base.filter((d) => online(d)).length
  return { all: base.length, online: on, offline: base.length - on }
})

onMounted(load)
async function load() {
  loading.value = true
  try {
    await Promise.all([wgStore.fetchPeers(), hostsStore.fetchHosts()])
  } finally {
    loading.value = false
  }
}

// ── online / status helpers ──
function online(d: DeviceRow): boolean {
  if (d._t === 'host') {
    if (d.is_self) return true // managed in-process
    if (!d.last_seen) return false
    const age = serverTimestampAgeMs(d.last_seen)
    return age !== null && age < 60_000
  }
  if (!d.latest_handshake) return false
  return Date.now() / 1000 - d.latest_handshake < 180
}
function hostStatus(d: HostRow): string {
  if (d.is_self) return t('hosts.status.local')
  if (!d.last_seen) return t('hosts.status.never')
  return online(d) ? t('hosts.status.online') : t('hosts.status.offline')
}

// ── toggle ──
async function toggle(d: DeviceRow) {
  if (d._t === 'client') {
    await wgStore.togglePeer(d.id, !d.enabled)
  } else {
    await hostsStore.updateHost(d.id, { enabled: !d.enabled })
  }
}

// ── host commands ──
async function cmd(d: HostRow, command: 'reload' | 'restart') {
  try {
    await hostsStore.enqueueCommand(d.id, command)
    notify(t('hosts.cmd.queued'))
  } catch {
    notify(t('hosts.cmd.failed'), false)
  }
}

// ── client create / edit ──
async function doCreateClient() {
  const { quota_gb, ...rest } = form.value
  await wgStore.createPeer({
    ...rest,
    address: form.value.address || undefined,
    quota_bytes: Math.round((quota_gb || 0) * GB),
  })
  showCreate.value = false
  form.value = { name: '', address: '', dns: '10.59.32.1', persistent_keepalive: 25, quota_gb: 0 }
}
function editClient(d: ClientRow) {
  editTarget.value = d
  editForm.value = {
    name: d.name, dns: d.dns,
    persistent_keepalive: d.persistent_keepalive,
    quota_gb: d.quota_bytes ? +(d.quota_bytes / GB).toFixed(2) : 0,
    allowed_ips: d.allowed_ips, notes: d.notes || '',
  }
}
async function doUpdateClient() {
  if (!editTarget.value) return
  const { quota_gb, ...rest } = editForm.value
  await wgStore.updatePeer(editTarget.value.id, { ...rest, quota_bytes: Math.round((quota_gb || 0) * GB) })
  editTarget.value = null
}

// ── delete (both kinds) ──
async function doDelete() {
  const d = deleteTarget.value
  if (!d) return
  if (d._t === 'client') await wgStore.deletePeer(d.id)
  else await hostsStore.deleteHost(d.id)
  deleteTarget.value = null
}

async function syncConfig() {
  await client.post('/wireguard/sync')
  await load()
}

// ── formatting ──
function usedBytes(p: WireGuardPeer) { return (p.transfer_rx || 0) + (p.transfer_tx || 0) }
function quotaPct(p: WireGuardPeer) { return p.quota_bytes ? Math.min(100, (usedBytes(p) / p.quota_bytes) * 100) : 0 }
function quotaClass(p: WireGuardPeer) {
  const q = quotaPct(p)
  return q >= 100 ? 'q-bad' : q >= 80 ? 'q-warn' : 'q-ok'
}
function formatTime(ts: number) { return new Date(ts * 1000).toLocaleString() }
function enrollmentExpiry(value: string) { return new Date(value.replace(' ', 'T') + 'Z').toLocaleString() }
function formatBytes(b: number) {
  if (b < 1024) return b + ' B'
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB'
  return (b / 1073741824).toFixed(2) + ' GB'
}
</script>

<style scoped>
.seg { display: inline-flex; gap: 2px; background: var(--paper-bg); border: 1px solid var(--paper-border); border-radius: var(--radius-sm); padding: 3px; }
.seg-btn {
  background: transparent; border: none; color: var(--ink-secondary);
  font-size: 0.8rem; font-weight: 550; padding: 0.35rem 0.85rem; border-radius: calc(var(--radius-sm) - 2px);
  cursor: pointer; display: inline-flex; align-items: center; gap: 0.4rem; transition: transform 0.1s;
}
.seg-btn:active { transform: scale(0.95); }
.seg-btn.active { background: var(--paper-surface); color: var(--accent); box-shadow: var(--paper-shadow); }
.seg-count { font-family: var(--font-mono); font-size: 0.66rem; opacity: 0.7; }

.filters { display: flex; flex-direction: column; gap: 0.6rem; align-items: flex-start; }
.filter-row { display: flex; align-items: center; gap: 0.6rem; }
.filter-label { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--ink-muted); min-width: 3.4rem; }

.device-card {
  padding: 1.75rem;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

/* Fill full width, auto-fit columns */
.device-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 1.75rem;
}
.device-top { display: flex; justify-content: space-between; align-items: flex-start; }
.device-name { font-size: 0.95rem; font-weight: 650; color: var(--ink-primary); display: flex; align-items: center; flex-wrap: wrap; gap: 0.1rem; }
.device-name-link { color: var(--ink-primary); text-decoration: none; }
.device-name-link:hover { color: var(--accent); text-decoration: underline; }

.type-badge {
  font-size: 0.58rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase;
  padding: 0.12rem 0.45rem; border-radius: 4px; margin-left: 0.5rem; vertical-align: middle;
}
.type-host { background: #f0ecfb; color: #6b4fa0; }
.type-client { background: #e8f5e8; color: #4a7c4a; }

.kind-badge {
  font-family: var(--font-mono); font-size: 0.55rem; font-weight: 700; letter-spacing: 0.05em;
  padding: 0.1rem 0.38rem; border-radius: 4px; margin-left: 0.35rem; vertical-align: middle;
}
.kind-agent { background: var(--accent-subtle); color: var(--accent); }
.kind-wg { background: #e8f0fe; color: #3c6ea8; }
.kind-self { background: var(--paper-border); color: var(--ink-secondary); }
.kind-android { background: #e9f4ff; color: #1769aa; }

.online-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 0.35rem; vertical-align: middle; }
.online-dot.on { background: var(--ok); box-shadow: 0 0 0 3px var(--ok-bg); }
.online-dot.off { background: #cbc4b8; }

.device-addr { font-family: var(--font-mono); font-size: 0.72rem; color: var(--ink-muted); margin-top: 0.15rem; display: block; }

.device-stats {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 0.75rem;
  padding: 0.75rem; background: var(--paper-bg); border-radius: var(--radius-sm);
  border: 1px solid var(--paper-border);
  box-shadow: inset 0 1px 3px rgba(0,0,0,.04);
  flex: 1;
}
.device-stat { display: flex; flex-direction: column; gap: 0.1rem; }
.device-stat-label { font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--ink-muted); }
.device-actions { display: flex; gap: 0.35rem; flex-wrap: wrap; margin-top: auto; padding-top: 0.25rem; }

.quota-bar { width: 100%; height: 5px; background: var(--paper-border); border-radius: 3px; margin-top: 0.3rem; overflow: hidden; }
.quota-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
.q-ok { background: var(--ok); }
.q-warn { background: var(--warn); }
.q-bad { background: var(--bad); }

.android-modal { width: min(760px, calc(100vw - 2rem)); }
.android-lead { margin: 0.45rem 0 1.25rem; line-height: 1.55; }
.android-enrollment-layout { display: grid; grid-template-columns: 260px 1fr; gap: 1.5rem; align-items: start; margin-top: 1rem; }
.android-qr { width: 260px; max-width: 100%; border: 1px solid var(--paper-border); border-radius: var(--radius-sm); background: white; padding: 0.5rem; }
.android-enrollment-info { display: flex; flex-direction: column; gap: 0.7rem; min-width: 0; }
.android-enrollment-info textarea { width: 100%; resize: vertical; font-family: var(--font-mono); font-size: 0.72rem; }
.enrollment-meta { display: flex; flex-direction: column; gap: 0.15rem; }
.enrollment-meta span { color: var(--ink-muted); font-size: 0.68rem; text-transform: uppercase; letter-spacing: .04em; }
.enrollment-meta strong { font-size: .82rem; overflow-wrap: anywhere; }
@media (max-width: 680px) {
  .android-enrollment-layout { grid-template-columns: 1fr; }
  .android-qr { margin: 0 auto; }
}
</style>
