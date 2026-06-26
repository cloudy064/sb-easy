<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.nodes.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.nodes.desc') }}</p>
      </div>
      <div class="flex-center gap-3">
        <HostSelect @change="load" />
        <button class="btn-secondary" @click="testAllNodes" :disabled="anyTesting" :title="'Delay-test all enabled nodes via the selected host'">
          {{ anyTesting ? 'Testing…' : 'Test all' }}
        </button>
        <button class="btn-secondary" @click="openImport">Import</button>
        <button class="btn-primary" @click="showCreate = true">Add Node</button>
      </div>
    </div>

    <!-- Latency-tier stats — click a chip to filter -->
    <div class="stat-bar">
      <button v-for="s in statChips" :key="s.key" class="stat-chip" :class="[s.cls, { active: tierFilter === s.key }]" @click="toggleTier(s.key)">
        <span class="stat-count">{{ s.count }}</span>
        <span class="stat-label">{{ s.label }}</span>
      </button>
    </div>

    <div class="flex-center gap-3 mb-5" style="flex-wrap:wrap">
      <input v-model="search" placeholder="Filter by name or tag..." style="max-width:240px" />
      <select v-model="filterType" style="max-width:140px">
        <option value="">All Protocols</option>
        <option value="shadowsocks">Shadowsocks</option>
        <option value="vmess">VMess</option>
        <option value="trojan">Trojan</option>
        <option value="vless">VLESS</option>
        <option value="hysteria2">Hysteria2</option>
        <option value="tuic">TUIC</option>
      </select>
      <select v-model="filterSource" style="max-width:170px">
        <option value="">All sources</option>
        <option value="__manual__">Manual</option>
        <option v-for="s in subs" :key="s.id" :value="s.id">{{ s.name }}</option>
      </select>
      <span class="text-xs text-muted" v-if="store.nodes.length">
        {{ filteredNodes.length }} of {{ store.nodes.length }} nodes
      </span>
    </div>

    <div v-if="store.loading" class="loading-center"><div class="spinner"></div></div>
    <div v-else-if="filteredNodes.length === 0" class="empty-state">
      <span class="empty-icon">···</span>
      <p>No proxy nodes found. Add nodes manually or import them from a subscription.</p>
    </div>

    <div v-else class="grid-2">
      <article v-for="node in filteredNodes" :key="node.id" class="card node-card">
        <div class="node-card-top">
          <div class="node-info">
            <div class="flex-center gap-2" style="flex-wrap:wrap">
              <span :class="['protocol-badge', protocolBadge(node.node_type)]">{{ protocolLabel(node.node_type) }}</span>
              <h3 class="node-tag truncate" style="max-width:170px">{{ node.tag }}</h3>
              <span class="source-badge" :class="node.subscription_id ? 'src-sub' : 'src-manual'">{{ sourceLabel(node) }}</span>
            </div>
            <span class="node-endpoint">{{ node.server }}<span class="text-muted">:{{ node.server_port }}</span></span>
          </div>
          <label class="toggle">
            <input type="checkbox" :checked="node.enabled" @change="toggleNode(node)" />
            <span class="slider"></span>
          </label>
        </div>

        <div class="node-card-bottom">
          <div class="latency-group">
            <span v-if="node.latency !== null" class="latency-value" :class="latencyColor(node.latency)">{{ node.latency }}<span class="latency-unit">ms</span></span>
            <span v-else-if="node.last_latency_test" class="latency-dead" title="Tested but unreachable — kept (it may come from a subscription)">✕ dead</span>
            <span v-else class="latency-untested">Not tested</span>
            <button class="latency-test-btn" :disabled="isTesting(node.id)" :title="isTesting(node.id) ? 'Testing…' : 'Test latency'" @click="testOne(node)">
              <span v-if="isTesting(node.id)" class="spinner-sm"></span>
              <svg v-else width="13" height="13" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.8">
                <path d="M15.5 9a6.5 6.5 0 1 1-2-4.7" stroke-linecap="round"/><path d="M15.5 3v3h-3"/>
              </svg>
            </button>
          </div>
          <div class="flex-center gap-2">
            <button class="btn-ghost btn-sm" @click="editNode(node)">Edit</button>
            <button class="btn-danger btn-sm" @click="confirmDelete(node)">Delete</button>
          </div>
        </div>
      </article>
    </div>

    <!-- Create Dialog -->
    <div v-if="showCreate" class="modal-overlay" @click.self="showCreate = false">
      <div class="modal">
        <h3>Add Proxy Node</h3>
        <form @submit.prevent="doCreate">
          <div class="form-group"><label>Tag (display name)</label><input v-model="createForm.tag" required placeholder="e.g. HK 01 | IEPL" /></div>
          <div class="form-group"><label>Protocol</label>
            <select v-model="createForm.node_type" required>
              <option value="shadowsocks">Shadowsocks</option>
              <option value="vmess">VMess</option>
              <option value="trojan">Trojan</option>
              <option value="vless">VLESS</option>
              <option value="hysteria2">Hysteria2</option>
              <option value="tuic">TUIC</option>
            </select>
          </div>
          <div style="display:grid;grid-template-columns:2fr 1fr;gap:1rem">
            <div class="form-group"><label>Server</label><input v-model="createForm.server" required placeholder="hostname or IP" /></div>
            <div class="form-group"><label>Port</label><input v-model.number="createForm.server_port" type="number" required /></div>
          </div>
          <!-- Shadowsocks fields -->
          <template v-if="createForm.node_type === 'shadowsocks'">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
              <div class="form-group"><label>Method</label><input v-model="ssConfig.method" placeholder="aes-256-gcm" /></div>
              <div class="form-group"><label>Password</label><input v-model="ssConfig.password" placeholder="password" /></div>
            </div>
          </template>
          <!-- VMess / VLESS fields -->
          <template v-if="createForm.node_type === 'vmess' || createForm.node_type === 'vless'">
            <div class="form-group"><label>UUID</label><input v-model="vmConfig.uuid" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" /></div>
          </template>
          <!-- Trojan / Hysteria2 fields -->
          <template v-if="createForm.node_type === 'trojan' || createForm.node_type === 'hysteria2'">
            <div class="form-group"><label>Password</label><input v-model="trConfig.password" placeholder="password" /></div>
          </template>

          <!-- Advanced: TLS / transport (not for shadowsocks) -->
          <template v-if="createForm.node_type !== 'shadowsocks'">
            <button type="button" class="btn-ghost btn-sm adv-toggle" @click="showAdvanced = !showAdvanced">
              {{ showAdvanced ? '▾' : '▸' }} Advanced (TLS / Reality / Transport)
            </button>
            <div v-if="showAdvanced" class="adv-box">
              <label class="adv-check">
                <input type="checkbox" v-model="adv.tlsEnabled" /> Enable TLS
              </label>
              <template v-if="adv.tlsEnabled">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
                  <div class="form-group"><label>SNI (server_name)</label><input v-model="adv.sni" placeholder="example.com" /></div>
                  <div class="form-group"><label>uTLS Fingerprint</label><input v-model="adv.fingerprint" placeholder="chrome" /></div>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
                  <div class="form-group"><label>ALPN (comma-sep)</label><input v-model="adv.alpn" placeholder="h2,http/1.1" /></div>
                  <label class="adv-check" style="align-self:center"><input type="checkbox" v-model="adv.insecure" /> Allow insecure</label>
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
                  <div class="form-group"><label>Reality public_key</label><input v-model="adv.realityPbk" placeholder="optional" /></div>
                  <div class="form-group"><label>Reality short_id</label><input v-model="adv.realitySid" placeholder="optional" /></div>
                </div>
              </template>
              <div class="form-group"><label>Transport</label>
                <select v-model="adv.transport">
                  <option value="">None (TCP)</option>
                  <option value="ws">WebSocket</option>
                  <option value="grpc">gRPC</option>
                  <option value="http">HTTP</option>
                </select>
              </div>
              <template v-if="adv.transport === 'ws' || adv.transport === 'http'">
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
                  <div class="form-group"><label>Path</label><input v-model="adv.path" placeholder="/" /></div>
                  <div class="form-group"><label>Host header</label><input v-model="adv.wsHost" placeholder="example.com" /></div>
                </div>
              </template>
              <template v-if="adv.transport === 'grpc'">
                <div class="form-group"><label>gRPC service_name</label><input v-model="adv.grpcService" placeholder="GunService" /></div>
              </template>
            </div>
          </template>

          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showCreate = false">Cancel</button>
            <button type="submit" class="btn-primary">Create Node</button>
          </div>
        </form>
      </div>
    </div>

    <!-- Import Dialog -->
    <div v-if="showImport" class="modal-overlay" @click.self="closeImport">
      <div class="modal">
        <h3>Import proxy nodes</h3>
        <p class="text-sm text-muted" style="margin-top:-0.3rem;margin-bottom:1rem">
          Pull nodes from an existing config profile or paste a sing-box config. This only fills the node list — it does <strong>not</strong> change any running config. Existing nodes are matched by fingerprint (no duplicates).
        </p>

        <div class="seg mb-4">
          <button class="seg-btn" :class="{ active: importSource === 'profile' }" @click="importSource = 'profile'">From profile</button>
          <button class="seg-btn" :class="{ active: importSource === 'paste' }" @click="importSource = 'paste'">Paste JSON</button>
        </div>

        <template v-if="importSource === 'profile'">
          <div class="form-group">
            <label>Config profile</label>
            <select v-model="importProfileId">
              <option value="" disabled>Select a profile…</option>
              <option v-for="p in profiles" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </div>
        </template>
        <template v-else>
          <div class="form-group">
            <label>sing-box config or outbounds array (JSON)</label>
            <textarea v-model="importPaste" rows="8" placeholder='{ "outbounds": [ … ] }  or  [ { "type": "shadowsocks", … } ]' style="width:100%;font-family:var(--font-mono);font-size:0.72rem"></textarea>
          </div>
        </template>

        <div v-if="importResult" class="import-result">
          <span class="badge badge-green">+{{ importResult.added }} added</span>
          <span class="badge badge-gray">{{ importResult.updated }} updated</span>
          <span class="badge badge-gray">{{ importResult.found }} found</span>
          <span v-if="importResult.skipped.length" class="badge badge-gray">{{ importResult.skipped.length }} skipped</span>
          <span v-if="importResult.errors.length" class="badge badge-red">{{ importResult.errors.length }} errors</span>
          <p v-if="importResult.errors.length" class="text-xs" style="margin-top:0.5rem;color:var(--bad)">{{ importResult.errors.join('; ') }}</p>
        </div>

        <div class="modal-actions">
          <button type="button" class="btn-secondary" @click="closeImport">Close</button>
          <button type="button" class="btn-primary" :disabled="importing || (importSource === 'profile' ? !importProfileId : !importPaste.trim())" @click="doImport">
            {{ importing ? 'Importing…' : 'Import' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Edit Dialog -->
    <div v-if="editTarget" class="modal-overlay" @click.self="editTarget = null">
      <div class="modal">
        <h3>Edit &ldquo;{{ editTarget.tag }}&rdquo;</h3>
        <form @submit.prevent="doUpdate">
          <div class="form-group"><label>Tag</label><input v-model="editForm.tag" /></div>
          <div class="form-group"><label>Server</label><input v-model="editForm.server" /></div>
          <div class="form-group"><label>Port</label><input v-model.number="editForm.server_port" type="number" /></div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="editTarget = null">Cancel</button>
            <button type="submit" class="btn-primary">Save</button>
          </div>
        </form>
      </div>
    </div>

    <!-- Delete -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal">
        <h3>Delete &ldquo;{{ deleteTarget.tag }}&rdquo;?</h3>
        <p class="text-sm text-muted">This node will be permanently removed from the database.</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="deleteTarget = null">Cancel</button>
          <button class="btn-danger" @click="doDelete">Delete</button>
        </div>
      </div>
    </div>

    <div v-if="toast" class="toast"><div class="toast-item toast-success">{{ toast }}</div></div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
const { t } = useI18n()
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import { useProxyNodesStore } from '../stores/proxyNodes'
import HostSelect from '../components/HostSelect.vue'
import { useHostTarget } from '../composables/hostTarget'
import client from '../api/client'
import type { ProxyNode, ConfigProfile, Subscription } from '../types'

const store = useProxyNodesStore()
const { reqParams } = useHostTarget()
const search = ref('')
const filterType = ref('')
const filterSource = ref('')
const subs = ref<Subscription[]>([])
const showCreate = ref(false)

// ── Import ──
const showImport = ref(false)
const importSource = ref<'profile' | 'paste'>('profile')
const importProfileId = ref('')
const importPaste = ref('')
const importing = ref(false)
const importResult = ref<{ found: number; added: number; updated: number; skipped: string[]; errors: string[] } | null>(null)
const profiles = ref<ConfigProfile[]>([])

async function openImport() {
  showImport.value = true
  importResult.value = null
  try {
    const { data } = await client.get('/hosts/profiles')
    profiles.value = Array.isArray(data) ? data : []
  } catch {
    profiles.value = []
  }
}
function closeImport() {
  showImport.value = false
  importPaste.value = ''
  importResult.value = null
}
async function doImport() {
  importing.value = true
  try {
    const body = importSource.value === 'profile'
      ? { profile_id: importProfileId.value }
      : { config: importPaste.value }
    importResult.value = await store.importNodes(body)
  } catch (e: any) {
    importResult.value = { found: 0, added: 0, updated: 0, skipped: [], errors: [e?.response?.data?.error || 'Import failed'] }
  } finally {
    importing.value = false
  }
}
const editTarget = ref<ProxyNode | null>(null)
const deleteTarget = ref<ProxyNode | null>(null)

const createForm = ref({ tag: '', node_type: 'shadowsocks', server: '', server_port: 443 })
const ssConfig = ref({ method: 'aes-256-gcm', password: '' })
const vmConfig = ref({ uuid: '' })
const trConfig = ref({ password: '' })
const editForm = ref({ tag: '', server: '', server_port: 443 })

const showAdvanced = ref(false)
const adv = ref({
  tlsEnabled: false, sni: '', fingerprint: '', alpn: '', insecure: false,
  realityPbk: '', realitySid: '',
  transport: '', path: '/', wsHost: '', grpcService: '',
})

function buildTls() {
  if (!adv.value.tlsEnabled) return undefined
  const tls: any = { enabled: true }
  if (adv.value.sni) tls.server_name = adv.value.sni
  if (adv.value.insecure) tls.insecure = true
  if (adv.value.alpn) tls.alpn = adv.value.alpn.split(',').map(s => s.trim()).filter(Boolean)
  if (adv.value.fingerprint) tls.utls = { enabled: true, fingerprint: adv.value.fingerprint }
  if (adv.value.realityPbk) {
    tls.reality = { enabled: true, public_key: adv.value.realityPbk, short_id: adv.value.realitySid || '' }
  }
  return tls
}

function buildTransport() {
  const t = adv.value.transport
  if (!t) return undefined
  if (t === 'ws') {
    const tr: any = { type: 'ws', path: adv.value.path || '/' }
    if (adv.value.wsHost) tr.headers = { Host: adv.value.wsHost }
    return tr
  }
  if (t === 'grpc') return { type: 'grpc', service_name: adv.value.grpcService || '' }
  if (t === 'http') {
    const tr: any = { type: 'http', path: adv.value.path || '/' }
    if (adv.value.wsHost) tr.host = [adv.value.wsHost]
    return tr
  }
  return undefined
}

function resetForm() {
  createForm.value = { tag: '', node_type: 'shadowsocks', server: '', server_port: 443 }
  ssConfig.value = { method: 'aes-256-gcm', password: '' }
  vmConfig.value = { uuid: '' }
  trConfig.value = { password: '' }
  showAdvanced.value = false
  adv.value = {
    tlsEnabled: false, sni: '', fingerprint: '', alpn: '', insecure: false,
    realityPbk: '', realitySid: '',
    transport: '', path: '/', wsHost: '', grpcService: '',
  }
}

onMounted(load)
async function load() {
  await Promise.all([store.fetchNodes(), fetchSubs()])
}
async function fetchSubs() {
  try {
    const { data } = await client.get('/subscriptions')
    subs.value = Array.isArray(data) ? data : []
  } catch {
    subs.value = []
  }
}

// Map a node to its source label: subscription name, or "Manual" for hand-added.
const subName = computed(() => Object.fromEntries(subs.value.map((s) => [s.id, s.name])))
function sourceLabel(n: ProxyNode): string {
  return n.subscription_id ? (subName.value[n.subscription_id] || 'Subscription') : 'Manual'
}

// ── Latency tiers ──
type Tier = 'fast' | 'normal' | 'high' | 'dead' | 'untested'
const tierFilter = ref<'' | Tier>('')
function tierOf(n: ProxyNode): Tier {
  if (n.latency != null) return n.latency < 200 ? 'fast' : n.latency < 500 ? 'normal' : 'high'
  return n.last_latency_test ? 'dead' : 'untested'
}
const stats = computed(() => {
  const s: Record<Tier, number> = { fast: 0, normal: 0, high: 0, dead: 0, untested: 0 }
  for (const n of store.nodes) s[tierOf(n)]++
  return s
})
const statChips = computed(() => [
  { key: '', label: t('proxies.tier.all'), cls: 'tier-all', count: store.nodes.length },
  { key: 'fast', label: t('proxies.tier.fast'), cls: 'tier-fast', count: stats.value.fast },
  { key: 'normal', label: t('proxies.tier.normal'), cls: 'tier-normal', count: stats.value.normal },
  { key: 'high', label: t('proxies.tier.high'), cls: 'tier-high', count: stats.value.high },
  { key: 'dead', label: t('proxies.tier.dead'), cls: 'tier-dead', count: stats.value.dead },
  { key: 'untested', label: t('proxies.tier.untested'), cls: 'tier-untested', count: stats.value.untested },
])
function toggleTier(k: string) { tierFilter.value = (tierFilter.value === k ? '' : k) as '' | Tier }

const filteredNodes = computed(() =>
  store.nodes.filter(n => {
    if (filterType.value && n.node_type !== filterType.value) return false
    if (filterSource.value === '__manual__' && n.subscription_id) return false
    if (filterSource.value && filterSource.value !== '__manual__' && n.subscription_id !== filterSource.value) return false
    if (tierFilter.value && tierOf(n) !== tierFilter.value) return false
    if (search.value && !n.tag.toLowerCase().includes(search.value.toLowerCase()) && !n.server.includes(search.value)) return false
    return true
  })
)

// ── Progressive per-node testing ──
// `testing[id]` drives the per-node spinner. A node clears when its
// last_latency_test changes from the snapshot taken when testing started — so
// results from the agent fill in one-by-one as it reports them.
const testing = reactive<Record<string, boolean>>({})
const anyTesting = computed(() => Object.keys(testing).length > 0)
function isTesting(id: string): boolean { return !!testing[id] }
let pollTimer: ReturnType<typeof setInterval> | null = null

function startTesting(ids: string[]): Record<string, string | null> {
  const snap: Record<string, string | null> = {}
  for (const id of ids) {
    testing[id] = true
    snap[id] = store.nodes.find(n => n.id === id)?.last_latency_test ?? null
  }
  return snap
}
function clearTesting() { for (const k of Object.keys(testing)) delete testing[k] }
function pollResults(snap: Record<string, string | null>) {
  if (pollTimer) clearInterval(pollTimer)
  let elapsed = 0
  pollTimer = setInterval(async () => {
    elapsed += 1.5
    await store.refreshLatencies() // in-place: no loading flash, no list flicker
    for (const n of store.nodes) {
      if (testing[n.id] && (n.last_latency_test ?? null) !== (snap[n.id] ?? null)) delete testing[n.id]
    }
    if (!anyTesting.value || elapsed > 180) {
      clearInterval(pollTimer!); pollTimer = null; clearTesting()
    }
  }, 1500)
}

async function testAllNodes() {
  const ids = store.nodes.filter(n => n.enabled).map(n => n.id)
  if (!ids.length) return
  const snap = startTesting(ids)
  const r = await store.testAll(reqParams.value as Record<string, string>)
  if (r.queued) { notify('Test dispatched — results fill in as each node completes.'); pollResults(snap) }
  else clearTesting() // local host: synchronous, latencies already patched
}
async function testOne(node: ProxyNode) {
  const snap = startTesting([node.id])
  const r = await store.testLatency(node.id, reqParams.value as Record<string, string>)
  if (r.queued) pollResults(snap)
  else delete testing[node.id]
}

onBeforeUnmount(() => { if (pollTimer) clearInterval(pollTimer) })

const toast = ref('')
function notify(msg: string) {
  toast.value = msg
  setTimeout(() => (toast.value = ''), 4000)
}

function protocolLabel(t: string) {
  return { shadowsocks:'SS', vmess:'VMess', trojan:'Trojan', vless:'VLESS', hysteria2:'HY2', tuic:'TUIC' }[t] || t
}
function protocolBadge(t: string) {
  return { shadowsocks:'proto-ss', vmess:'proto-vmess', trojan:'proto-trojan', vless:'proto-vless', hysteria2:'proto-hy2', tuic:'proto-tuic' }[t] || 'proto-default'
}
function latencyColor(ms: number) {
  if (ms < 200) return 'latency-good'
  if (ms < 500) return 'latency-ok'
  return 'latency-slow'
}

async function doCreate() {
  let config: any = {}
  const type = createForm.value.node_type
  if (type === 'shadowsocks') config = { method: ssConfig.value.method, password: ssConfig.value.password }
  else if (type === 'vmess') config = { uuid: vmConfig.value.uuid, alter_id: 0, security: 'auto' }
  else if (type === 'vless') config = { uuid: vmConfig.value.uuid, flow: '', packet_encoding: 'xudp' }
  else if (type === 'trojan') config = { password: trConfig.value.password }
  else if (type === 'hysteria2') config = { password: trConfig.value.password }

  if (type !== 'shadowsocks') {
    const tls = buildTls()
    const transport = buildTransport()
    if (tls) config.tls = tls
    if (transport) config.transport = transport
  }

  await store.createNode({ ...createForm.value, protocol_config: config, enabled: true })
  showCreate.value = false
  resetForm()
}

function editNode(node: ProxyNode) {
  editTarget.value = node
  editForm.value = { tag: node.tag, server: node.server, server_port: node.server_port }
}
async function doUpdate() {
  if (!editTarget.value) return
  await store.updateNode(editTarget.value.id, editForm.value)
  editTarget.value = null
}

function confirmDelete(node: ProxyNode) { deleteTarget.value = node }
async function doDelete() {
  if (!deleteTarget.value) return
  await store.deleteNode(deleteTarget.value.id)
  deleteTarget.value = null
}

async function toggleNode(node: ProxyNode) {
  await store.updateNode(node.id, { enabled: !node.enabled })
  node.enabled = !node.enabled
}
</script>

<style scoped>
.node-card {
  padding: 1.75rem;
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}

.node-card-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.node-tag {
  font-size: 0.9rem;
  font-weight: 600;
  color: var(--ink-primary);
}

.node-endpoint {
  font-family: var(--font-mono);
  font-size: 0.7rem;
  color: var(--ink-secondary);
  margin-top: 0.3rem;
  display: block;
}

.node-card-bottom {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.latency-display {
  display: flex;
  align-items: baseline;
  gap: 0.15rem;
}
.latency-value {
  font-size: 1.05rem;
  font-weight: 680;
}
.latency-unit { font-size: 0.7rem; margin-left: 0.15rem; opacity: 0.6; }
.latency-good { color: var(--ok); }
.latency-ok   { color: var(--warn); }
.latency-slow { color: var(--bad); }
.latency-untested { color: var(--ink-muted); font-size: 0.78rem; font-style: italic; }
.latency-dead { color: var(--bad); font-size: 0.82rem; font-weight: 600; }

/* Protocol badges */
.protocol-badge {
  font-family: var(--font-mono);
  font-size: 0.6rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  padding: 0.15rem 0.45rem;
  border-radius: 4px;
  text-transform: uppercase;
}
.proto-ss      { background: #e8f0fe; color: #3c6ea8; }
.proto-vmess   { background: #e8f5e8; color: #4a7c4a; }
.proto-trojan  { background: #faf2e0; color: #8a6c2c; }
.proto-vless   { background: #faeceb; color: #9c4a44; }
.proto-hy2     { background: var(--paper-border); color: #6b6259; }
.proto-tuic    { background: #ecf4f7; color: #4a6c7c; }
.proto-default { background: #f3f0ea; color: var(--ink-muted); }

.adv-toggle { padding-left: 0; margin-bottom: 0.5rem; color: var(--accent); }
.adv-box {
  border: none;
  border-radius: var(--radius-sm);
  padding: 1rem;
  background: var(--paper-bg);
  box-shadow: var(--nm-shadow-sm-in);
  margin-bottom: 1.1rem;
}
.adv-check {
  display: flex; align-items: center; gap: 0.5rem;
  font-size: 0.82rem; color: var(--ink-secondary); margin-bottom: 0.85rem;
}

.seg { display: inline-flex; gap: 2px; background: var(--paper-bg); border: none; border-radius: var(--radius-sm); padding: 4px; box-shadow: var(--nm-shadow-sm-in); }
.seg-btn {
  background: transparent; border: none; color: var(--ink-secondary);
  font-size: 0.8rem; font-weight: 550; padding: 0.35rem 0.85rem; border-radius: calc(var(--radius-sm) - 3px);
  cursor: pointer; display: inline-flex; align-items: center; gap: 0.4rem;
}
.seg-btn.active { background: var(--paper-bg); color: var(--accent); box-shadow: var(--nm-shadow-sm-out); }
.import-result { display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; margin: 0.25rem 0 0.5rem; }

.source-badge {
  font-size: 0.58rem; font-weight: 650; letter-spacing: 0.02em;
  padding: 0.1rem 0.4rem; border-radius: 4px; max-width: 120px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.src-sub { background: #eef0fb; color: #5a5fa0; }
.src-manual { background: var(--paper-border); color: var(--ink-muted); }

/* Latency-tier stats bar */
.stat-bar { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
.stat-chip {
  display: flex; align-items: baseline; gap: 0.4rem;
  background: var(--paper-bg); border: none;
  border-radius: var(--radius-sm); padding: 0.4rem 0.75rem; cursor: pointer;
  box-shadow: var(--nm-shadow-sm-out);
  transition: box-shadow 0.2s, transform 0.2s;
}
.stat-chip:hover { box-shadow: 5px 5px 10px var(--nm-dark), -5px -5px 10px var(--nm-light); }
.stat-chip.active { box-shadow: var(--nm-shadow-sm-in); color: var(--accent); }
.stat-count { font-size: 1.05rem; font-weight: 680; font-family: var(--font-mono); }
.stat-label { font-size: 0.72rem; font-weight: 600; color: var(--ink-secondary); }
.tier-fast .stat-count { color: var(--ok); }
.tier-normal .stat-count { color: var(--warn); }
.tier-high .stat-count { color: #d08a3c; }
.tier-dead .stat-count { color: var(--bad); }
.tier-untested .stat-count { color: var(--ink-muted); }
.tier-all .stat-count { color: var(--ink-primary); }

/* Inline per-node test button + spinner */
.latency-group { display: flex; align-items: baseline; gap: 0.5rem; }
.latency-test-btn {
  display: inline-flex; align-items: center; justify-content: center;
  width: 24px; height: 24px; padding: 0; border-radius: 6px;
  background: var(--paper-bg); border: none;
  box-shadow: var(--nm-shadow-sm-out);
  color: var(--ink-secondary); cursor: pointer; align-self: center; flex-shrink: 0;
  transition: all 0.15s;
}
.latency-test-btn:hover:not(:disabled) { color: var(--accent); box-shadow: var(--nm-shadow-sm-in); }
.latency-test-btn:active:not(:disabled) { box-shadow: var(--nm-shadow-sm-in); transform: scale(0.92); }
.spinner-sm {
  width: 13px; height: 13px; border-radius: 50%;
  border: 2px solid var(--accent-subtle); border-top-color: var(--accent);
  animation: spin 0.7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
</style>
