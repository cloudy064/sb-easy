<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.devices.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.devices.desc') }}</p>
      </div>
      <div class="flex-center gap-3">
        <button class="btn-secondary btn-sm" @click="syncConfig">Sync Config</button>
        <button class="btn-secondary btn-sm" @click="showCreate = true">{{ t('devices.add.wireguard') }}</button>
        <button class="btn-primary" @click="openEnrollment()">{{ t('devices.add.device') }}</button>
      </div>
    </div>

    <!-- Platform and runtime are device metadata, not separate device types. -->
    <div class="filters mb-5">
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
              <template v-if="d._t === 'client'">
                <span class="kind-badge kind-wg">WIREGUARD</span>
                <span v-if="d.expired" class="badge badge-red" style="margin-left:0.4rem">Expired</span>
              </template>
              <template v-else>
                <span v-if="d.is_self" class="kind-badge kind-self">SELF</span>
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
            <button class="btn-ghost btn-sm" @click="openQrCenter(d)">{{ t('devices.qr.open') }}</button>
            <button class="btn-danger btn-sm" @click="deleteTarget = d">Delete</button>
          </template>
          <template v-else>
            <button class="btn-ghost btn-sm" :disabled="d.is_self" @click="cmd(d, 'reload')">{{ t('hosts.reload') }}</button>
            <button class="btn-ghost btn-sm" :disabled="d.is_self" @click="cmd(d, 'restart')">{{ t('hosts.restart') }}</button>
            <button v-if="!d.is_self" class="btn-ghost btn-sm" @click="openQrCenter(d)">{{ t('devices.qr.open') }}</button>
            <button class="btn-ghost btn-sm" @click="openManage(d)">{{ t('hosts.edit') }}</button>
            <button class="btn-danger btn-sm" :disabled="d.is_self" @click="deleteTarget = d">Delete</button>
          </template>
        </div>
      </article>
    </div>

    <!-- Raw WireGuard credential for devices that do not run the managed agent. -->
    <div v-if="showCreate" class="modal-overlay" @click.self="showCreate = false">
      <div class="modal">
        <h3>{{ t('devices.add.wireguard') }}</h3>
        <form @submit.prevent="doCreateClient">
          <div class="form-group"><label>Name</label><input v-model="form.name" required placeholder="e.g. office-pc" /></div>
          <div class="form-group"><label>Address</label><input v-model="form.address" placeholder="Auto-assign if left empty (10.59.32.x/24)" /></div>
          <div class="form-group"><label>DNS Server</label><input v-model="form.dns" placeholder="10.59.32.1" /></div>
          <div class="form-group"><label>Persistent Keepalive (seconds)</label><input v-model.number="form.persistent_keepalive" type="number" /></div>
          <div class="form-group"><label>Traffic Quota (GB, 0 = unlimited)</label><input v-model.number="form.quota_gb" type="number" min="0" step="0.5" /></div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showCreate = false">Cancel</button>
            <button type="submit" class="btn-primary">{{ t('devices.add.wireguard') }}</button>
          </div>
        </form>
      </div>
    </div>

    <!-- One enrollment flow for every managed device. The device reports its
         platform only after it has redeemed the shared one-time code. -->
    <div v-if="showEnrollment" class="modal-overlay" @click.self="closeEnrollment">
      <div class="modal enrollment-modal">
        <template v-if="!deviceEnrollment">
          <h3>{{ t('device.enroll.title') }}</h3>
          <p class="text-sm text-muted enrollment-lead">{{ t('device.enroll.hint') }}</p>
          <form @submit.prevent="createDeviceEnrollment">
            <div class="form-group">
              <label>{{ t('device.enroll.name') }}</label>
              <input v-model.trim="deviceName" required :placeholder="t('device.enroll.name.placeholder')" />
            </div>
            <div class="form-group">
              <label>{{ t('hosts.profile') }}</label>
              <select v-model="deviceProfileId">
                <option v-for="profile in hostsStore.profiles" :key="profile.id" :value="profile.id">{{ profile.name }}</option>
              </select>
            </div>
            <div class="modal-actions">
              <button type="button" class="btn-secondary" @click="closeEnrollment">{{ t('action.cancel') }}</button>
              <button type="submit" class="btn-primary" :disabled="deviceCreating">
                {{ deviceCreating ? t('device.enroll.creating') : t('device.enroll.create') }}
              </button>
            </div>
          </form>
        </template>
        <template v-else>
          <h3>{{ t('device.enroll.ready') }}</h3>
          <p class="text-sm text-muted enrollment-lead">{{ t('device.enroll.scan') }}</p>
          <div class="qr-kind-label sb-easy-kind">{{ t('devices.qr.sbeasy.badge') }}</div>
          <div class="enrollment-layout">
            <img :src="deviceQrSrc" :alt="t('device.enroll.qr.alt')" class="enrollment-qr" />
            <div class="enrollment-info">
              <div class="enrollment-meta">
                <span>{{ t('device.enroll.server') }}</span>
                <strong>{{ deviceEnrollment.server }}</strong>
              </div>
              <div class="enrollment-meta">
                <span>{{ t('device.enroll.expires') }}</span>
                <strong>{{ enrollmentExpiry(deviceEnrollment.expires_at) }}</strong>
              </div>
              <label class="text-sm">{{ t('device.enroll.native') }}</label>
              <div class="cmd-box"><code>{{ enrollmentCommand }}</code></div>
              <label class="text-sm">{{ t('device.enroll.manual') }}</label>
              <textarea readonly rows="3" :value="deviceEnrollment.enrollment_uri"></textarea>
              <button class="btn-secondary btn-sm" @click="copyEnrollment">{{ t('action.copy') }}</button>
            </div>
          </div>
          <div class="modal-actions">
            <button class="btn-secondary" @click="closeEnrollment">{{ t('action.close') }}</button>
            <button class="btn-primary" @click="resetEnrollment">{{ t('device.enroll.another') }}</button>
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

    <!-- One QR center, with protocol-specific payloads kept explicit. -->
    <div v-if="qrTarget" class="modal-overlay" @click.self="closeQrCenter">
      <div class="modal qr-center-modal">
        <div class="qr-center-head">
          <div>
            <h3>{{ t('devices.qr.title') }} &mdash; {{ qrTarget.name }}</h3>
            <p class="text-sm text-muted">{{ t('devices.qr.subtitle') }}</p>
          </div>
          <button class="btn-ghost btn-sm" @click="closeQrCenter">{{ t('action.close') }}</button>
        </div>

        <div class="qr-tabs" role="tablist" :aria-label="t('devices.qr.title')">
          <button class="qr-tab" :class="{ active: qrMode === 'sbeasy' }" role="tab" :aria-selected="qrMode === 'sbeasy'" @click="selectQrMode('sbeasy')">
            {{ t('devices.qr.tab.sbeasy') }}
          </button>
          <button class="qr-tab" :class="{ active: qrMode === 'wireguard' }" role="tab" :aria-selected="qrMode === 'wireguard'" @click="selectQrMode('wireguard')">
            {{ t('devices.qr.tab.wireguard') }}
          </button>
          <button class="qr-tab" :class="{ active: qrMode === 'singbox' }" role="tab" :aria-selected="qrMode === 'singbox'" @click="selectQrMode('singbox')">
            {{ t('devices.qr.tab.singbox') }}
          </button>
        </div>

        <section v-if="qrMode === 'sbeasy'" class="qr-panel">
          <div class="qr-kind-label sb-easy-kind">{{ t('devices.qr.sbeasy.badge') }}</div>
          <h4>{{ t('devices.qr.sbeasy.title') }}</h4>
          <p class="text-sm text-muted qr-explanation">{{ t('devices.qr.sbeasy.desc') }}</p>

          <template v-if="qrTarget._t === 'host'">
            <div v-if="qrEnrollment" class="qr-result-layout">
              <img :src="qrEnrollmentSrc" :alt="t('device.enroll.qr.alt')" class="enrollment-qr" />
              <div class="qr-result-copy">
                <div class="enrollment-meta">
                  <span>{{ t('device.enroll.expires') }}</span>
                  <strong>{{ enrollmentExpiry(qrEnrollment.expires_at) }}</strong>
                </div>
                <label class="text-sm">{{ t('device.enroll.manual') }}</label>
                <textarea readonly rows="4" :value="qrEnrollment.enrollment_uri"></textarea>
                <button class="btn-secondary btn-sm" @click="copyQrEnrollment">{{ t('action.copy') }}</button>
              </div>
            </div>
            <div v-else class="qr-empty-action">
              <p>{{ t('devices.qr.sbeasy.generate.hint') }}</p>
              <button class="btn-primary" :disabled="qrEnrollmentCreating" @click="createQrEnrollment">
                {{ qrEnrollmentCreating ? t('device.enroll.creating') : t('devices.qr.sbeasy.generate') }}
              </button>
            </div>
          </template>
          <div v-else class="qr-warning-card">
            <strong>{{ t('devices.qr.sbeasy.wgonly.title') }}</strong>
            <p>{{ t('devices.qr.sbeasy.wgonly.desc') }}</p>
            <button class="btn-primary" @click="startManagedEnrollment">{{ t('devices.qr.sbeasy.wgonly.action') }}</button>
          </div>
        </section>

        <section v-else-if="qrMode === 'wireguard'" class="qr-panel">
          <div class="qr-kind-label wireguard-kind">WIREGUARD</div>
          <h4>{{ t('devices.qr.wireguard.title') }}</h4>
          <p class="text-sm qr-protocol-warning">{{ t('devices.qr.wireguard.warning') }}</p>
          <template v-if="qrWireGuardPeer">
            <img v-if="qrWireGuardSrc" :src="qrWireGuardSrc" :alt="t('devices.qr.wireguard.alt')" class="enrollment-qr qr-centered" />
            <div v-else-if="!qrError" class="spinner qr-spinner"></div>
          </template>
          <div v-else class="qr-unavailable">{{ t('devices.qr.wireguard.unavailable') }}</div>
        </section>

        <section v-else class="qr-panel">
          <div class="qr-kind-label singbox-kind">SING-BOX</div>
          <h4>{{ t('devices.qr.singbox.title') }}</h4>
          <p class="text-sm text-muted qr-explanation">{{ t('devices.qr.singbox.desc') }}</p>
          <div class="qr-flow">
            <span>{{ t('devices.qr.flow.scan') }}</span><b>→</b>
            <span>{{ t('devices.qr.flow.authorize') }}</span><b>→</b>
            <span>{{ t('devices.qr.flow.sync') }}</span>
          </div>
          <p class="text-sm qr-protocol-warning">{{ t('devices.qr.singbox.compat') }}</p>
        </section>

        <p v-if="qrError" class="text-sm qr-error">{{ qrError }}</p>
      </div>
    </div>

    <!-- Delete confirm -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal">
        <h3>Delete &ldquo;{{ deleteTarget.name }}&rdquo;?</h3>
        <p class="text-sm text-muted">
          {{ deleteTarget._t === 'host' ? t('hosts.delete.hint') : t('devices.delete.wireguard.hint') }}
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
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'
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

const statusFilter = ref<'all' | 'online' | 'offline'>('all')
const loading = ref(false)
const showCreate = ref(false)
const showEnrollment = ref(false)
const deviceName = ref('')
const deviceProfileId = ref('android-client')
const deviceCreating = ref(false)
const deviceEnrollment = ref<AgentEnrollment | null>(null)
const deviceHostId = ref<string | null>(null)
const editTarget = ref<WireGuardPeer | null>(null)
const deleteTarget = ref<DeviceRow | null>(null)
type QrMode = 'sbeasy' | 'wireguard' | 'singbox'
const qrTarget = ref<DeviceRow | null>(null)
const qrMode = ref<QrMode>('sbeasy')
const qrWireGuardSrc = ref('')
const qrEnrollment = ref<AgentEnrollment | null>(null)
const qrEnrollmentCreating = ref(false)
const qrError = ref('')

const deviceQrSrc = computed(() => deviceEnrollment.value
  ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(deviceEnrollment.value.qr_svg)}`
  : '')
const enrollmentCommand = computed(() => deviceEnrollment.value
  ? `SB_EASY_SERVER=${deviceEnrollment.value.server} AGENT_ENROLLMENT_CODE=${deviceEnrollment.value.code} sb-easy-agent`
  : '')
const qrEnrollmentSrc = computed(() => qrEnrollment.value
  ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(qrEnrollment.value.qr_svg)}`
  : '')
const qrWireGuardPeer = computed<WireGuardPeer | null>(() => {
  const target = qrTarget.value
  if (!target) return null
  return target._t === 'client' ? target : target.wg
})

async function openEnrollment(initialName = '') {
  if (hostsStore.profiles.length === 0) await hostsStore.fetchProfiles()
  deviceName.value = initialName
  deviceProfileId.value = hostsStore.profiles.some((profile) => profile.id === 'android-client')
    ? 'android-client'
    : (hostsStore.profiles[0]?.id ?? 'default')
  deviceEnrollment.value = null
  deviceHostId.value = null
  showEnrollment.value = true
}
function closeEnrollment() {
  showEnrollment.value = false
  deviceEnrollment.value = null
  deviceName.value = ''
  deviceHostId.value = null
}
function resetEnrollment() {
  deviceEnrollment.value = null
  deviceName.value = ''
  deviceHostId.value = null
}
async function createDeviceEnrollment() {
  if (!deviceName.value || deviceCreating.value) return
  deviceCreating.value = true
  try {
    if (!deviceHostId.value) {
      const host = await hostsStore.createHost({
        name: deviceName.value,
        profile_id: deviceProfileId.value,
        capabilities: {
          runs_singbox: true,
          is_wg_member: false,
          is_wg_hub: false,
          is_self: false,
        },
      })
      deviceHostId.value = host.id
    }
    deviceEnrollment.value = await hostsStore.createEnrollment(deviceHostId.value)
  } catch (error) {
    notify(error instanceof Error ? error.message : t('device.enroll.failed'), false)
  } finally {
    deviceCreating.value = false
  }
}
async function copyEnrollment() {
  if (!deviceEnrollment.value) return
  await navigator.clipboard.writeText(deviceEnrollment.value.enrollment_uri)
  notify(t('action.copied'))
}

function revokeWireGuardQr() {
  if (!qrWireGuardSrc.value) return
  window.URL.revokeObjectURL(qrWireGuardSrc.value)
  qrWireGuardSrc.value = ''
}
function openQrCenter(target: DeviceRow) {
  revokeWireGuardQr()
  qrTarget.value = target
  qrMode.value = 'sbeasy'
  qrEnrollment.value = null
  qrEnrollmentCreating.value = false
  qrError.value = ''
}
function closeQrCenter() {
  revokeWireGuardQr()
  qrTarget.value = null
  qrEnrollment.value = null
  qrEnrollmentCreating.value = false
  qrError.value = ''
}
function selectQrMode(mode: QrMode) {
  qrMode.value = mode
  qrError.value = ''
  if (mode === 'wireguard') void loadWireGuardQr()
}
async function loadWireGuardQr() {
  const peer = qrWireGuardPeer.value
  if (!peer || qrWireGuardSrc.value) return
  const requestedPeerId = peer.id
  try {
    const src = await wgStore.fetchQR(requestedPeerId)
    if (qrWireGuardPeer.value?.id === requestedPeerId && qrMode.value === 'wireguard') {
      qrWireGuardSrc.value = src
    } else {
      window.URL.revokeObjectURL(src)
    }
  } catch (error) {
    qrError.value = error instanceof Error ? error.message : t('devices.qr.load.failed')
  }
}
async function createQrEnrollment() {
  const target = qrTarget.value
  if (!target || target._t !== 'host' || qrEnrollmentCreating.value) return
  qrEnrollmentCreating.value = true
  qrError.value = ''
  try {
    qrEnrollment.value = await hostsStore.createEnrollment(target.id)
  } catch (error) {
    qrError.value = error instanceof Error ? error.message : t('device.enroll.failed')
  } finally {
    qrEnrollmentCreating.value = false
  }
}
async function copyQrEnrollment() {
  if (!qrEnrollment.value) return
  await navigator.clipboard.writeText(qrEnrollment.value.enrollment_uri)
  notify(t('action.copied'))
}
async function startManagedEnrollment() {
  const suggestedName = qrTarget.value?.name ?? ''
  closeQrCenter()
  await openEnrollment(suggestedName)
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

function byStatus(list: DeviceRow[]): DeviceRow[] {
  if (statusFilter.value === 'online') return list.filter((d) => online(d))
  if (statusFilter.value === 'offline') return list.filter((d) => !online(d))
  return list
}

const allDevices = computed<DeviceRow[]>(() => [...hostRows.value, ...clientRows.value])
const devices = computed<DeviceRow[]>(() => byStatus(allDevices.value))
const statusCounts = computed(() => {
  const base = allDevices.value
  const on = base.filter((d) => online(d)).length
  return { all: base.length, online: on, offline: base.length - on }
})

let refreshTimer: ReturnType<typeof setInterval> | null = null
let refreshInFlight = false

onMounted(async () => {
  await load(true)
  refreshTimer = setInterval(() => { void load(false) }, 10_000)
})
onBeforeUnmount(() => {
  if (refreshTimer) clearInterval(refreshTimer)
  revokeWireGuardQr()
})

async function load(showLoading = true) {
  if (refreshInFlight) return
  refreshInFlight = true
  if (showLoading) loading.value = true
  try {
    await Promise.all([wgStore.fetchPeers(), hostsStore.fetchHosts()])
  } finally {
    refreshInFlight = false
    if (showLoading) loading.value = false
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

.kind-badge {
  font-family: var(--font-mono); font-size: 0.55rem; font-weight: 700; letter-spacing: 0.05em;
  padding: 0.1rem 0.38rem; border-radius: 4px; margin-left: 0.35rem; vertical-align: middle;
}
.kind-wg { background: #e8f0fe; color: #3c6ea8; }
.kind-self { background: var(--paper-border); color: var(--ink-secondary); }

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

.enrollment-modal { width: min(760px, calc(100vw - 2rem)); }
.enrollment-lead { margin: 0.45rem 0 1.25rem; line-height: 1.55; }
.enrollment-layout { display: grid; grid-template-columns: 260px 1fr; gap: 1.5rem; align-items: start; margin-top: 1rem; }
.enrollment-qr { width: 260px; max-width: 100%; border: 1px solid var(--paper-border); border-radius: var(--radius-sm); background: white; padding: 0.5rem; }
.enrollment-info { display: flex; flex-direction: column; gap: 0.7rem; min-width: 0; }
.enrollment-info textarea { width: 100%; resize: vertical; font-family: var(--font-mono); font-size: 0.72rem; }
.cmd-box { background: var(--paper-bg); border: 1px solid var(--paper-border); border-radius: var(--radius-sm); padding: 0.75rem; font-family: var(--font-mono); font-size: 0.72rem; overflow-wrap: anywhere; color: var(--ink-primary); }
.enrollment-meta { display: flex; flex-direction: column; gap: 0.15rem; }
.enrollment-meta span { color: var(--ink-muted); font-size: 0.68rem; text-transform: uppercase; letter-spacing: .04em; }
.enrollment-meta strong { font-size: .82rem; overflow-wrap: anywhere; }
.qr-kind-label {
  display: inline-flex; width: fit-content; align-items: center; padding: .25rem .55rem;
  border-radius: 999px; font-family: var(--font-mono); font-size: .62rem;
  font-weight: 750; letter-spacing: .045em;
}
.sb-easy-kind { color: var(--accent); background: color-mix(in srgb, var(--accent) 12%, transparent); border: 1px solid color-mix(in srgb, var(--accent) 30%, transparent); }
.wireguard-kind { color: #3c6ea8; background: #e8f0fe; border: 1px solid #c7daf6; }
.singbox-kind { color: #7952a8; background: #f0e9fa; border: 1px solid #ddcdf2; }
.qr-center-modal { width: min(720px, calc(100vw - 2rem)); }
.qr-center-head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; }
.qr-center-head p { margin-top: .35rem; line-height: 1.5; }
.qr-tabs {
  display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 3px;
  margin: 1.25rem 0; padding: 4px; border: 1px solid var(--paper-border);
  border-radius: var(--radius-sm); background: var(--paper-bg);
}
.qr-tab {
  border: 0; border-radius: calc(var(--radius-sm) - 3px); padding: .65rem .7rem;
  color: var(--ink-secondary); background: transparent; font-size: .78rem;
  font-weight: 650; cursor: pointer;
}
.qr-tab.active { color: var(--accent); background: var(--paper-surface); box-shadow: var(--paper-shadow); }
.qr-panel { min-height: 330px; display: flex; flex-direction: column; align-items: flex-start; }
.qr-panel h4 { margin: .75rem 0 .4rem; font-size: 1.05rem; }
.qr-explanation { line-height: 1.6; max-width: 620px; }
.qr-result-layout { width: 100%; display: grid; grid-template-columns: 250px 1fr; gap: 1.35rem; margin-top: 1rem; align-items: start; }
.qr-result-copy { display: flex; flex-direction: column; gap: .65rem; min-width: 0; }
.qr-result-copy textarea { width: 100%; resize: vertical; font-family: var(--font-mono); font-size: .72rem; }
.qr-empty-action, .qr-warning-card, .qr-unavailable {
  width: 100%; margin-top: 1rem; padding: 1rem; border: 1px solid var(--paper-border);
  border-radius: var(--radius-sm); background: var(--paper-bg); line-height: 1.55;
}
.qr-empty-action p, .qr-warning-card p { margin: 0 0 .8rem; color: var(--ink-secondary); font-size: .82rem; }
.qr-protocol-warning { width: 100%; margin: .4rem 0 1rem; padding: .7rem .8rem; border-radius: var(--radius-sm); color: #8b4a18; background: #fff3df; border: 1px solid #f1d6a7; line-height: 1.5; }
.qr-centered { margin: .3rem auto 0; }
.qr-spinner { margin: 3rem auto; }
.qr-flow { display: flex; flex-wrap: wrap; align-items: center; gap: .55rem; margin: 1.2rem 0; }
.qr-flow span { padding: .55rem .7rem; border: 1px solid var(--paper-border); border-radius: var(--radius-sm); background: var(--paper-bg); font-size: .76rem; font-weight: 650; }
.qr-flow b { color: var(--ink-muted); }
.qr-error { width: 100%; margin-top: .8rem; color: var(--bad); }
@media (max-width: 680px) {
  .enrollment-layout { grid-template-columns: 1fr; }
  .enrollment-qr { margin: 0 auto; }
  .qr-center-head { align-items: center; }
  .qr-tabs { grid-template-columns: 1fr; }
  .qr-result-layout { grid-template-columns: 1fr; }
  .qr-flow { align-items: stretch; flex-direction: column; width: 100%; }
  .qr-flow b { transform: rotate(90deg); align-self: center; }
}
</style>
