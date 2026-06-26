<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.hosts.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.hosts.desc') }}</p>
      </div>
      <button class="btn-primary" @click="openCreate">{{ t('hosts.add') }}</button>
    </div>

    <div v-if="store.loading" class="loading-center"><div class="spinner"></div></div>
    <div v-else-if="store.hosts.length === 0" class="empty-state">
      <span class="empty-icon">···</span>
      <p>{{ t('hosts.empty') }}</p>
    </div>

    <div v-else class="grid-2">
      <article v-for="h in store.hosts" :key="h.id" class="card host-card">
        <div class="host-top">
          <div class="host-info">
            <div class="flex-center gap-2">
              <span class="status-dot" :class="statusClass(h)" :title="statusText(h)"></span>
              <h3 class="host-name truncate" style="max-width:200px">{{ h.name }}</h3>
            </div>
            <span class="host-meta">
              {{ statusText(h) }}
              <span v-if="h.wg_address" class="host-wg">· {{ h.wg_address }}</span>
            </span>
          </div>
          <label class="toggle" :title="h.enabled ? 'Enabled' : 'Disabled'">
            <input type="checkbox" :checked="h.enabled" :disabled="h.capabilities.is_self" @change="toggleEnabled(h)" />
            <span class="slider"></span>
          </label>
        </div>

        <div class="cap-row">
          <span v-if="h.capabilities.is_self" class="cap-badge cap-self">SELF</span>
          <span v-if="h.capabilities.is_wg_hub" class="cap-badge cap-hub">WG HUB</span>
          <span v-if="h.capabilities.is_wg_member" class="cap-badge cap-wg">WG</span>
          <span v-if="h.wg_endpoint" class="cap-badge cap-mesh" :title="h.wg_endpoint">MESH</span>
          <span v-if="h.capabilities.runs_singbox" class="cap-badge cap-sb">sing-box</span>
          <span class="cap-badge cap-out">{{ h.assigned_outbounds ? h.assigned_outbounds + ' proxies' : 'all proxies' }}</span>
          <span v-if="h.config_drift" class="cap-badge cap-drift" :title="t('hosts.drift.hint')">{{ t('hosts.drift') }}</span>
        </div>

        <div class="host-bottom">
          <span class="host-sb-state">{{ singboxState(h) }}</span>
          <div class="flex-center gap-2">
            <button v-if="!h.capabilities.is_self" class="btn-ghost btn-sm" @click="openEdit(h)">{{ t('hosts.edit') }}</button>
            <button v-if="!h.capabilities.is_self" class="btn-ghost btn-sm" @click="sendCmd(h, 'reload')">{{ t('hosts.reload') }}</button>
            <button v-if="!h.capabilities.is_self" class="btn-ghost btn-sm" @click="sendCmd(h, 'restart')">{{ t('hosts.restart') }}</button>
            <button class="btn-ghost btn-sm" @click="openOutbounds(h)">{{ t('hosts.proxies') }}</button>
            <button v-if="!h.capabilities.is_self && h.capabilities.is_wg_member && h.wg_address" class="btn-ghost btn-sm" @click="store.downloadWgConfig(h)">{{ t('hosts.wgconfig') }}</button>
            <button v-if="!h.capabilities.is_self" class="btn-ghost btn-sm" @click="openInstall(h)">{{ t('hosts.install') }}</button>
            <button v-if="!h.capabilities.is_self" class="btn-danger btn-sm" @click="deleteTarget = h">{{ t('action.delete') }}</button>
          </div>
        </div>
      </article>
    </div>

    <!-- Create -->
    <div v-if="showCreate" class="modal-overlay" @click.self="showCreate = false">
      <div class="modal">
        <h3>{{ t('hosts.add') }}</h3>
        <form @submit.prevent="doCreate">
          <div class="form-group"><label>{{ t('hosts.name') }}</label><input v-model="form.name" required placeholder="e.g. edge-hk-01" /></div>
          <div class="form-group"><label>{{ t('hosts.profile') }}</label>
            <select v-model="form.profile_id">
              <option v-for="p in store.profiles" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </div>
          <div class="cap-checks">
            <label class="adv-check"><input type="checkbox" v-model="form.caps.runs_singbox" /> {{ t('hosts.cap.singbox') }}</label>
            <label class="adv-check"><input type="checkbox" v-model="form.caps.is_wg_member" /> {{ t('hosts.cap.wg') }}</label>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
            <div class="form-group"><label>{{ t('hosts.wgaddr') }}</label><input v-model="form.wg_address" placeholder="10.59.32.10/32" /></div>
            <div class="form-group"><label>{{ t('hosts.clash') }}</label><input v-model="form.clash_api" placeholder="http://10.59.32.10:9090" /></div>
          </div>
          <p class="text-xs text-muted" style="margin:-0.4rem 0 0.9rem">{{ t('hosts.clash.hint') }}</p>
          <div class="form-group"><label>{{ t('hosts.endpoint') }}</label><input v-model="form.wg_endpoint" placeholder="203.0.113.10:51820" /></div>
          <p class="text-xs text-muted" style="margin:-0.4rem 0 0.9rem">{{ t('hosts.endpoint.hint') }}</p>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showCreate = false">{{ t('action.cancel') }}</button>
            <button type="submit" class="btn-primary">{{ t('hosts.create') }}</button>
          </div>
        </form>
      </div>
    </div>

    <!-- Edit host -->
    <div v-if="editTarget" class="modal-overlay" @click.self="editTarget = null">
      <div class="modal">
        <h3>{{ t('hosts.edit') }} — {{ editTarget.name }}</h3>
        <form @submit.prevent="doEdit">
          <div class="form-group"><label>{{ t('hosts.name') }}</label><input v-model="editForm.name" required /></div>
          <div class="form-group"><label>{{ t('hosts.profile') }}</label>
            <select v-model="editForm.profile_id">
              <option v-for="p in store.profiles" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </div>
          <div class="cap-checks">
            <label class="adv-check"><input type="checkbox" v-model="editForm.caps.runs_singbox" /> {{ t('hosts.cap.singbox') }}</label>
            <label class="adv-check"><input type="checkbox" v-model="editForm.caps.is_wg_member" /> {{ t('hosts.cap.wg') }}</label>
          </div>
          <div class="form-group"><label>{{ t('hosts.endpoint') }}</label><input v-model="editForm.wg_endpoint" placeholder="203.0.113.10:51820" /></div>
          <div class="form-group"><label>{{ t('hosts.clash') }}</label><input v-model="editForm.clash_api" placeholder="http://10.59.32.10:9090" /></div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="editTarget = null">{{ t('action.cancel') }}</button>
            <button type="submit" class="btn-primary">{{ t('action.save') }}</button>
          </div>
        </form>
      </div>
    </div>

    <!-- Install command / token -->
    <div v-if="installTarget" class="modal-overlay" @click.self="installTarget = null">
      <div class="modal">
        <h3>{{ t('hosts.install') }} — {{ installTarget.name }}</h3>
        <p class="text-sm text-muted">{{ t('hosts.install.hint') }}</p>
        <div class="cmd-box">
          <code>{{ installCommand }}</code>
        </div>
        <div class="flex-center gap-2" style="margin-top:0.75rem;justify-content:flex-end">
          <button class="btn-ghost btn-sm" @click="copyInstall">{{ copied ? t('action.copied') : t('action.copy') }}</button>
          <button class="btn-secondary btn-sm" @click="doRotate">{{ t('hosts.rotate') }}</button>
        </div>
        <div class="modal-actions">
          <button class="btn-secondary" @click="installTarget = null">{{ t('action.close') }}</button>
        </div>
      </div>
    </div>

    <!-- Outbound assignment -->
    <div v-if="outboundTarget" class="modal-overlay" @click.self="outboundTarget = null">
      <div class="modal">
        <h3>{{ t('hosts.proxies') }} — {{ outboundTarget.name }}</h3>
        <p class="text-sm text-muted">{{ t('hosts.proxies.hint') }}</p>
        <div class="proxy-pick">
          <label v-for="n in nodesStore.nodes" :key="n.id" class="proxy-pick-item">
            <input type="checkbox" :value="n.id" v-model="selectedNodes" />
            <span class="truncate">{{ n.tag }}</span>
            <span class="text-xs text-muted">{{ n.node_type }}</span>
          </label>
          <p v-if="nodesStore.nodes.length === 0" class="text-sm text-muted">No proxies yet.</p>
        </div>
        <p class="text-xs text-muted">{{ selectedNodes.length === 0 ? t('hosts.proxies.all') : selectedNodes.length + ' selected' }}</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="outboundTarget = null">{{ t('action.cancel') }}</button>
          <button class="btn-primary" @click="saveOutbounds">{{ t('action.save') }}</button>
        </div>
      </div>
    </div>

    <div v-if="toast" class="toast"><div class="toast-item toast-success">{{ toast }}</div></div>

    <!-- Delete -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal">
        <h3>{{ t('hosts.delete.q') }} &ldquo;{{ deleteTarget.name }}&rdquo;?</h3>
        <p class="text-sm text-muted">{{ t('hosts.delete.hint') }}</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="deleteTarget = null">{{ t('action.cancel') }}</button>
          <button class="btn-danger" @click="doDelete">{{ t('action.delete') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from '../composables/i18n'
import { useHostsStore } from '../stores/hosts'
import { useProxyNodesStore } from '../stores/proxyNodes'
import type { Host } from '../types'

const { t } = useI18n()
const store = useHostsStore()
const nodesStore = useProxyNodesStore()

const showCreate = ref(false)
const editTarget = ref<Host | null>(null)
const editForm = ref({ name: '', profile_id: 'default', caps: { runs_singbox: true, is_wg_member: true }, wg_endpoint: '', clash_api: '' })
const installTarget = ref<Host | null>(null)
const outboundTarget = ref<Host | null>(null)
const deleteTarget = ref<Host | null>(null)
const selectedNodes = ref<string[]>([])
const installCommand = ref('')
const copied = ref(false)
const toast = ref('')

async function sendCmd(h: Host, command: 'reload' | 'restart') {
  try {
    await store.enqueueCommand(h.id, command)
    showToast(t('hosts.cmd.queued') + ` (${command})`)
  } catch {
    showToast(t('hosts.cmd.failed'))
  }
}
function showToast(msg: string) {
  toast.value = msg
  setTimeout(() => (toast.value = ''), 2200)
}

const form = ref({
  name: '',
  profile_id: 'default',
  caps: { runs_singbox: true, is_wg_member: true },
  wg_address: '',
  wg_endpoint: '',
  clash_api: '',
})

onMounted(async () => {
  await Promise.all([store.fetchHosts(), store.fetchProfiles(), nodesStore.fetchNodes()])
})

function openCreate() {
  form.value = { name: '', profile_id: 'default', caps: { runs_singbox: true, is_wg_member: true }, wg_address: '', wg_endpoint: '', clash_api: '' }
  showCreate.value = true
}

async function doCreate() {
  await store.createHost({
    name: form.value.name,
    profile_id: form.value.profile_id,
    capabilities: { ...form.value.caps },
    wg_address: form.value.wg_address || undefined,
    wg_endpoint: form.value.wg_endpoint || undefined,
    clash_api: form.value.clash_api || undefined,
  })
  showCreate.value = false
}

function openEdit(h: Host) {
  editTarget.value = h
  editForm.value = {
    name: h.name,
    profile_id: h.profile_id || 'default',
    caps: { runs_singbox: h.capabilities.runs_singbox, is_wg_member: h.capabilities.is_wg_member },
    wg_endpoint: h.wg_endpoint || '',
    clash_api: h.clash_api || '',
  }
}

async function doEdit() {
  if (!editTarget.value) return
  // Preserve hub/self flags the form doesn't expose.
  const caps = { ...editTarget.value.capabilities, ...editForm.value.caps }
  await store.updateHost(editTarget.value.id, {
    name: editForm.value.name,
    profile_id: editForm.value.profile_id,
    capabilities: caps,
    wg_endpoint: editForm.value.wg_endpoint,
    clash_api: editForm.value.clash_api,
  } as any)
  editTarget.value = null
  await store.fetchHosts()
}

// ── Online status ────────────────────────────────────────────
function secondsSinceSeen(h: Host): number | null {
  if (!h.last_seen) return null
  const ts = Date.parse(h.last_seen)
  if (Number.isNaN(ts)) return null
  return (Date.now() - ts) / 1000
}
function isOnline(h: Host): boolean {
  const s = secondsSinceSeen(h)
  return s !== null && s < 90
}
function statusClass(h: Host) {
  if (h.capabilities.is_self) return 'dot-self'
  return isOnline(h) ? 'dot-online' : 'dot-offline'
}
function statusText(h: Host): string {
  if (h.capabilities.is_self) return t('hosts.status.local')
  const s = secondsSinceSeen(h)
  if (s === null) return t('hosts.status.never')
  if (s < 90) return t('hosts.status.online')
  return t('hosts.status.offline')
}
function singboxState(h: Host): string {
  if (!h.singbox_state) return ''
  try {
    const st = JSON.parse(h.singbox_state)
    const running = st.running === true ? '●' : st.running === false ? '○' : ''
    return [running, st.version].filter(Boolean).join(' ')
  } catch { return '' }
}

async function toggleEnabled(h: Host) {
  await store.updateHost(h.id, { enabled: !h.enabled })
  h.enabled = !h.enabled
}

// ── Install / token ──────────────────────────────────────────
async function openInstall(h: Host) {
  installTarget.value = h
  copied.value = false
  const { agent_token, server } = await store.revealToken(h.id)
  installCommand.value = buildCommand(server, agent_token)
}
function buildCommand(server: string, token: string) {
  const base = server.startsWith('http') ? server : `http://${server}:51821`
  return `SB_EASY_SERVER=${base} AGENT_TOKEN=${token} sb-easy-agent`
}
async function doRotate() {
  if (!installTarget.value) return
  const token = await store.rotateToken(installTarget.value.id)
  const { server } = await store.revealToken(installTarget.value.id)
  installCommand.value = buildCommand(server, token)
  copied.value = false
}
function copyInstall() {
  navigator.clipboard?.writeText(installCommand.value)
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}

// ── Outbound assignment ──────────────────────────────────────
async function openOutbounds(h: Host) {
  outboundTarget.value = h
  selectedNodes.value = await store.getOutbounds(h.id)
}
async function saveOutbounds() {
  if (!outboundTarget.value) return
  await store.setOutbounds(outboundTarget.value.id, selectedNodes.value)
  outboundTarget.value = null
}

async function doDelete() {
  if (!deleteTarget.value) return
  await store.deleteHost(deleteTarget.value.id)
  deleteTarget.value = null
}
</script>

<style scoped>
.host-card { padding: 1.6rem; display: flex; flex-direction: column; gap: 0.85rem; }
.host-top { display: flex; justify-content: space-between; align-items: flex-start; }
.host-name { font-size: 0.95rem; font-weight: 640; color: var(--ink-primary); }
.host-meta { font-size: 0.7rem; color: var(--ink-muted); margin-top: 0.3rem; display: block; }
.host-wg { font-family: var(--font-mono); color: var(--ink-secondary); }

.status-dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; display: inline-block; }
.dot-online { background: var(--ok); box-shadow: 0 0 0 3px var(--ok-bg); }
.dot-offline { background: var(--bad); }
.dot-self { background: var(--accent); }

.cap-row { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.cap-badge {
  font-family: var(--font-mono); font-size: 0.58rem; font-weight: 700;
  letter-spacing: 0.05em; padding: 0.13rem 0.42rem; border-radius: 4px; text-transform: uppercase;
}
.cap-self { background: var(--accent-subtle); color: var(--accent); }
.cap-hub  { background: #faf2e0; color: #8a6c2c; }
.cap-wg   { background: #e8f0fe; color: #3c6ea8; }
.cap-mesh { background: #ecf4f7; color: #4a6c7c; }
.cap-sb   { background: #e8f5e8; color: #4a7c4a; }
.cap-out  { background: var(--paper-border); color: var(--ink-muted); }
.cap-drift { background: var(--bad-bg); color: var(--bad); }

.host-bottom { display: flex; justify-content: space-between; align-items: center; }
.host-sb-state { font-family: var(--font-mono); font-size: 0.72rem; color: var(--ink-secondary); }

.cap-checks { display: flex; gap: 1.25rem; margin-bottom: 1rem; }
.adv-check { display: flex; align-items: center; gap: 0.5rem; font-size: 0.82rem; color: var(--ink-secondary); }

.cmd-box {
  background: var(--paper-bg); border: none; box-shadow: var(--nm-shadow-sm-in);
  border-radius: var(--radius-sm); padding: 0.85rem; margin-top: 0.75rem;
  font-family: var(--font-mono); font-size: 0.72rem; word-break: break-all; color: var(--ink-primary);
}

.proxy-pick { max-height: 320px; overflow-y: auto; display: flex; flex-direction: column; gap: 2px; margin: 0.5rem 0; }
.proxy-pick-item {
  display: flex; align-items: center; gap: 0.6rem; padding: 0.45rem 0.5rem;
  border-radius: var(--radius-sm); font-size: 0.84rem;
}
.proxy-pick-item:hover { background: var(--paper-bg); }
</style>
