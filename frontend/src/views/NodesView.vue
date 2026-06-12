<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>Nodes</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">Manage proxy outbound nodes. Import via subscriptions or add manually.</p>
      </div>
      <button class="btn-primary" @click="showCreate = true">Add Node</button>
    </div>

    <div class="flex-center gap-3 mb-5" style="flex-wrap:wrap">
      <input v-model="search" placeholder="Filter by name or tag..." style="max-width:260px" />
      <select v-model="filterType" style="max-width:150px">
        <option value="">All Protocols</option>
        <option value="shadowsocks">Shadowsocks</option>
        <option value="vmess">VMess</option>
        <option value="trojan">Trojan</option>
        <option value="vless">VLESS</option>
        <option value="hysteria2">Hysteria2</option>
        <option value="tuic">TUIC</option>
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
            <div class="flex-center gap-2">
              <span :class="['protocol-badge', protocolBadge(node.node_type)]">{{ protocolLabel(node.node_type) }}</span>
              <h3 class="node-tag truncate" style="max-width:200px">{{ node.tag }}</h3>
            </div>
            <span class="node-endpoint">{{ node.server }}<span class="text-muted">:{{ node.server_port }}</span></span>
          </div>
          <label class="toggle">
            <input type="checkbox" :checked="node.enabled" @change="toggleNode(node)" />
            <span class="slider"></span>
          </label>
        </div>

        <div class="node-card-bottom">
          <div class="latency-display">
            <template v-if="node.latency !== null">
              <span class="latency-value" :class="latencyColor(node.latency)">{{ node.latency }}<span class="latency-unit">ms</span></span>
            </template>
            <template v-else>
              <span class="latency-untested">Not tested</span>
            </template>
          </div>
          <div class="flex-center gap-2">
            <button class="btn-ghost btn-sm" @click="testLatency(node.id)">Test</button>
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
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showCreate = false">Cancel</button>
            <button type="submit" class="btn-primary">Create Node</button>
          </div>
        </form>
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
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useProxyNodesStore } from '../stores/proxyNodes'
import type { ProxyNode } from '../types'

const store = useProxyNodesStore()
const search = ref('')
const filterType = ref('')
const showCreate = ref(false)
const editTarget = ref<ProxyNode | null>(null)
const deleteTarget = ref<ProxyNode | null>(null)

const createForm = ref({ tag: '', node_type: 'shadowsocks', server: '', server_port: 443 })
const ssConfig = ref({ method: 'aes-256-gcm', password: '' })
const vmConfig = ref({ uuid: '' })
const trConfig = ref({ password: '' })
const editForm = ref({ tag: '', server: '', server_port: 443 })

onMounted(() => store.fetchNodes())

const filteredNodes = computed(() =>
  store.nodes.filter(n => {
    if (filterType.value && n.node_type !== filterType.value) return false
    if (search.value && !n.tag.toLowerCase().includes(search.value.toLowerCase()) && !n.server.includes(search.value)) return false
    return true
  })
)

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
  if (createForm.value.node_type === 'shadowsocks') config = { method: ssConfig.value.method, password: ssConfig.value.password }
  else if (createForm.value.node_type === 'vmess') config = { uuid: vmConfig.value.uuid, alter_id: 0, security: 'auto' }
  else if (createForm.value.node_type === 'vless') config = { uuid: vmConfig.value.uuid, flow: '', packet_encoding: 'xudp' }
  else if (createForm.value.node_type === 'trojan') config = { password: trConfig.value.password }
  else if (createForm.value.node_type === 'hysteria2') config = { password: trConfig.value.password }
  await store.createNode({ ...createForm.value, protocol_config: config, enabled: true })
  showCreate.value = false
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

async function testLatency(id: string) { await store.testLatency(id) }
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
.proto-hy2     { background: #f5f1ea; color: #6b6259; }
.proto-tuic    { background: #ecf4f7; color: #4a6c7c; }
.proto-default { background: #f3f0ea; color: var(--ink-muted); }
</style>
