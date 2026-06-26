<template>
  <div class="dashboard">
    <div class="page-header">
      <h2>{{ t('page.dashboard.title') }}</h2>
      <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.dashboard.desc') }}</p>
    </div>

    <!-- Stat cards — always 4 columns -->
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-icon stat-icon-wg">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="1" y="3" width="18" height="14" rx="2"/><circle cx="5" cy="7" r="1.2" fill="currentColor"/><circle cx="5" cy="13" r="1.2" fill="currentColor"/></svg>
        </div>
        <div class="stat-body">
          <div class="stat-label">Clients</div>
          <div class="stat-value">{{ stats.wgPeers }}</div>
          <div class="stat-sub" v-if="stats.wgActive > 0">{{ stats.wgActive }} online</div>
          <div class="stat-sub muted" v-else>none active</div>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon stat-icon-node">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="10" cy="10" r="7"/><circle cx="10" cy="10" r="2"/><line x1="10" y1="3" x2="10" y2="17"/><line x1="3" y1="10" x2="17" y2="10"/></svg>
        </div>
        <div class="stat-body">
          <div class="stat-label">Nodes</div>
          <div class="stat-value">{{ stats.nodes }}</div>
          <div class="stat-sub muted">{{ stats.nodeTypes }} protocols</div>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon stat-icon-sub">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M1 7l5-5 3 3 10-5"/><path d="M1 14l5-5 3 3 10-5"/></svg>
        </div>
        <div class="stat-body">
          <div class="stat-label">Subscriptions</div>
          <div class="stat-value">{{ stats.subs }}</div>
          <div class="stat-sub" v-if="stats.subsActive > 0">{{ stats.subsActive }} active</div>
          <div class="stat-sub muted" v-else>none active</div>
        </div>
      </div>

      <div class="stat-card">
        <div class="stat-icon stat-icon-sys">
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="10" cy="10" r="3"/><path d="M10 1v2M10 17v2M1 10h2M17 10h2M3.34 3.34l1.42 1.42M15.24 15.24l1.42 1.42M3.34 16.66l1.42-1.42M15.24 4.76l1.42-1.42"/></svg>
        </div>
        <div class="stat-body">
          <div class="stat-label">System</div>
          <div class="stat-value" style="font-size:1.1rem;font-weight:650">
            <span class="status-dot"></span>Running
          </div>
          <div class="stat-sub muted">v{{ stats.version || '—' }}</div>
        </div>
      </div>
    </div>

    <!-- Lists section — two columns -->
    <div class="list-grid">
      <!-- Clients list -->
      <div class="card dash-card">
        <div class="dash-card-header">
          <h3 class="card-title">Clients</h3>
          <router-link to="/devices?filter=clients" class="dash-card-link">View all</router-link>
        </div>
        <div v-if="wgPeers.length === 0" class="empty-inline text-sm text-muted">No peers configured yet.</div>
        <div v-else class="dash-list">
          <div v-for="p in wgPeers.slice(0, 8)" :key="p.id" class="dash-list-row">
            <div class="dash-list-main">
              <span class="dash-dot" :class="p.enabled && p.latest_handshake ? 'on' : 'off'"></span>
              <span class="dash-list-name">{{ p.name }}</span>
            </div>
            <div class="dash-list-meta">
              <span class="dash-addr">{{ p.address }}</span>
              <span v-if="p.transfer_rx" class="dash-bw">↓ {{ formatBytes(p.transfer_rx) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Nodes & traffic -->
      <div class="card dash-card">
        <div class="dash-card-header">
          <h3 class="card-title">Nodes by Latency</h3>
          <router-link to="/proxies" class="dash-card-link">View all</router-link>
        </div>
        <div v-if="sortedNodes.length === 0" class="empty-inline text-sm text-muted">No latency data yet.</div>
        <div v-else class="dash-list">
          <div v-for="n in sortedNodes.slice(0, 8)" :key="n.id" class="dash-list-row">
            <div class="dash-list-main truncate" style="max-width:240px">
              <span class="proto-badge" :class="'proto-' + n.node_type">{{ n.node_type }}</span>
              {{ n.tag }}
            </div>
            <span :class="latencyClass(n.latency)">{{ n.latency ? n.latency + 'ms' : '—' }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
const { t } = useI18n()
import { ref, computed, onMounted } from 'vue'
import { useWireGuardStore } from '../stores/wireguard'
import { useProxyNodesStore } from '../stores/proxyNodes'
import { useSubscriptionsStore } from '../stores/subscriptions'
import client from '../api/client'

const wgStore = useWireGuardStore()
const nodeStore = useProxyNodesStore()
const subStore = useSubscriptionsStore()

const stats = ref({ wgPeers: 0, wgActive: 0, nodes: 0, nodeTypes: 0, subs: 0, subsActive: 0, version: '' })

onMounted(async () => {
  const [, , , status] = await Promise.all([
    wgStore.fetchPeers(),
    nodeStore.fetchNodes(),
    subStore.fetchAll(),
    client.get('/system/status').then(r => r.data).catch(() => ({})),
  ])
  stats.value = {
    wgPeers: wgStore.peers.length,
    wgActive: wgStore.peers.filter(p => p.enabled && p.latest_handshake).length,
    nodes: nodeStore.nodes.length,
    nodeTypes: new Set(nodeStore.nodes.map(n => n.node_type)).size,
    subs: subStore.subs.length,
    subsActive: subStore.subs.filter(s => s.enabled).length,
    version: status?.version || '',
  }
})

const wgPeers = computed(() => wgStore.peers)
const sortedNodes = computed(() =>
  [...nodeStore.nodes].filter(n => n.latency !== null).sort((a, b) => (a.latency || 9999) - (b.latency || 9999))
)

function latencyClass(ms: number | null) {
  if (ms === null) return 'latency-badge muted'
  if (ms < 200) return 'latency-badge fast'
  if (ms < 500) return 'latency-badge mid'
  return 'latency-badge slow'
}

function formatBytes(b: number) {
  if (b < 1024) return b + ' B'
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB'
  return (b / 1073741824).toFixed(2) + ' GB'
}
</script>

<style scoped>
.dashboard { display: flex; flex-direction: column; gap: 2rem; }

/* ── Stat cards ───────────────────────────────────── */
.stat-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1.5rem;
}

.stat-card {
  background: var(--paper-surface);
  border: 1px solid var(--paper-border);
  border-radius: var(--radius-lg);
  padding: 1.5rem 1.6rem;
  box-shadow: var(--paper-shadow-card);
  display: flex;
  align-items: center;
  gap: 1.1rem;
  transition: box-shadow 0.2s, border-color 0.2s;
}
.stat-card:hover {
  border-color: var(--paper-border-hover);
  box-shadow: var(--paper-shadow-hover);
}

.stat-icon {
  width: 42px; height: 42px;
  border-radius: var(--radius-sm);
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
}
.stat-icon-wg  { background: var(--ok-bg); color: var(--ok); }
.stat-icon-node { background: var(--info-bg); color: var(--info); }
.stat-icon-sub { background: var(--warn-bg); color: var(--warn); }
.stat-icon-sys { background: var(--accent-subtle); color: var(--accent); }

.stat-body { flex: 1; min-width: 0; }
.stat-label {
  font-size: 0.7rem; font-weight: 600; color: var(--ink-muted);
  text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.2rem;
}
.stat-value {
  font-size: 1.7rem; font-weight: 680; color: var(--ink-primary);
  line-height: 1.15; font-variant-numeric: tabular-nums;
}
.stat-sub { font-size: 0.72rem; font-weight: 550; color: var(--ok); margin-top: 0.15rem; }
.stat-sub.muted { color: var(--ink-muted); }
.status-dot {
  display: inline-block; width: 9px; height: 9px; border-radius: 50%;
  background: var(--ok); margin-right: 0.4rem; vertical-align: middle;
}

/* ── List grid ─────────────────────────────────────── */
.list-grid {
  display: grid;
  grid-template-columns: 3fr 2fr;
  gap: 1.75rem;
}

.dash-card {
  padding: 1.5rem 1.75rem;
  display: flex;
  flex-direction: column;
}

.dash-card-header {
  display: flex; justify-content: space-between; align-items: baseline;
  margin-bottom: 0.5rem;
}
.card-title {
  font-size: 0.88rem; font-weight: 650; color: var(--ink-primary);
  padding-bottom: 0.65rem; margin-bottom: 0;
  border-bottom: 1px solid var(--paper-border);
}
.dash-card-link {
  font-size: 0.75rem; font-weight: 550; color: var(--accent); text-decoration: none;
  white-space: nowrap; margin-left: 1rem;
}
.dash-card-link:hover { color: var(--accent-hover); }

.dash-list { flex: 1; }
.dash-list-row {
  display: flex; justify-content: space-between; align-items: center;
  padding: 0.5rem 0; border-bottom: 1px solid var(--paper-border); gap: 0.75rem;
}
.dash-list-row:last-child { border-bottom: none; }

.dash-list-main { display: flex; align-items: center; gap: 0.5rem; min-width: 0; }
.dash-dot {
  width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0;
}
.dash-dot.on  { background: var(--ok); box-shadow: 0 0 0 2px var(--ok-bg); }
.dash-dot.off { background: var(--paper-border); }

.dash-list-name { font-size: 0.84rem; font-weight: 520; color: var(--ink-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.dash-list-meta { display: flex; align-items: center; gap: 0.6rem; flex-shrink: 0; }
.dash-addr { font-family: var(--font-mono); font-size: 0.7rem; color: var(--ink-muted); }
.dash-bw { font-size: 0.72rem; color: var(--info); font-family: var(--font-mono); white-space: nowrap; }

.proto-badge {
  font-family: var(--font-mono); font-size: 0.58rem; font-weight: 700; letter-spacing: 0.04em;
  text-transform: uppercase; padding: 0.1rem 0.35rem; border-radius: 3px; flex-shrink: 0;
}
.proto-shadowsocks { background: #e8f5e8; color: #4a7c4a; }
.proto-vmess       { background: #e8f0fe; color: #3c6ea8; }
.proto-trojan      { background: #f5e8f5; color: #7c4a7c; }
.proto-vless       { background: #fef3e8; color: #a87a3c; }
.proto-hysteria2   { background: #fce8e8; color: #b8443c; }
.proto-tuic        { background: #e8f4f7; color: #4a6c7c; }

.latency-badge {
  font-family: var(--font-mono); font-size: 0.72rem; font-weight: 600;
  padding: 0.15rem 0.5rem; border-radius: 9999px; flex-shrink: 0;
}
.latency-badge.fast  { color: var(--ok); background: var(--ok-bg); }
.latency-badge.mid   { color: var(--warn); background: var(--warn-bg); }
.latency-badge.slow  { color: var(--bad); background: var(--bad-bg); }
.latency-badge.muted { color: var(--ink-muted); background: var(--paper-bg); }

.empty-inline { padding: 1.5rem 0; text-align: center; }

/* ── Responsive ────────────────────────────────────── */
@media (max-width: 900px) {
  .stat-grid { grid-template-columns: repeat(2, 1fr); }
  .list-grid { grid-template-columns: 1fr; }
}
@media (max-width: 500px) {
  .stat-grid { grid-template-columns: 1fr; }
}
</style>
