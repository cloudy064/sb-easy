<template>
  <div>
    <div class="page-header">
      <h2>{{ t('page.dashboard.title') }}</h2>
      <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.dashboard.desc') }}</p>
    </div>

    <div class="grid-4" style="margin-bottom:2.25rem">
      <div class="stat-card">
        <div class="stat-label">Clients</div>
        <div class="stat-value">
          {{ stats.wgPeers }}
          <span class="badge badge-green" v-if="stats.wgActive > 0">{{ stats.wgActive }} active</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Nodes</div>
        <div class="stat-value">
          {{ stats.nodes }}
          <span class="badge badge-blue">{{ stats.nodeTypes }} protocols</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Subscriptions</div>
        <div class="stat-value">
          {{ stats.subs }}
          <span class="badge badge-green" v-if="stats.subsActive > 0">{{ stats.subsActive }} active</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-label">System Status</div>
        <div class="stat-value">
          <span class="status-dot"></span>
          Running
        </div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <h3 class="card-title">Clients</h3>
        <div v-if="wgPeers.length === 0" class="text-sm text-muted" style="padding:1rem 0">No peers configured yet.</div>
        <div v-else>
          <div v-for="p in wgPeers.slice(0, 5)" :key="p.id" class="list-row">
            <div>
              <div class="list-row-name">{{ p.name }}</div>
              <div class="text-xs text-muted">{{ p.address }}</div>
            </div>
            <span :class="p.enabled ? 'badge badge-green' : 'badge badge-gray'" style="font-size:0.65rem">
              {{ p.enabled ? 'Active' : 'Disabled' }}
            </span>
          </div>
        </div>
      </div>

      <div class="card">
        <h3 class="card-title">Nodes by Latency</h3>
        <div v-if="sortedNodes.length === 0" class="text-sm text-muted" style="padding:1rem 0">No nodes with latency data yet.</div>
        <div v-else>
          <div v-for="n in sortedNodes.slice(0, 8)" :key="n.id" class="list-row">
            <div class="truncate" style="max-width:220px">
              <span class="protocol-tag">{{ n.node_type }}</span>
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

const wgStore = useWireGuardStore()
const nodeStore = useProxyNodesStore()
const subStore = useSubscriptionsStore()

const stats = ref({ wgPeers: 0, wgActive: 0, nodes: 0, nodeTypes: 0, subs: 0, subsActive: 0 })

onMounted(async () => {
  await Promise.all([wgStore.fetchPeers(), nodeStore.fetchNodes(), subStore.fetchAll()])
  stats.value = {
    wgPeers: wgStore.peers.length,
    wgActive: wgStore.peers.filter(p => p.enabled).length,
    nodes: nodeStore.nodes.length,
    nodeTypes: new Set(nodeStore.nodes.map(n => n.node_type)).size,
    subs: subStore.subs.length,
    subsActive: subStore.subs.filter(s => s.enabled).length,
  }
})

const wgPeers = computed(() => wgStore.peers)
const sortedNodes = computed(() =>
  [...nodeStore.nodes].filter(n => n.latency !== null).sort((a, b) => (a.latency || 9999) - (b.latency || 9999))
)

function latencyClass(ms: number | null) {
  if (ms === null) return 'text-sm text-muted'
  if (ms < 200) return 'badge badge-green'
  if (ms < 500) return 'badge badge-yellow'
  return 'badge badge-red'
}
</script>

<style scoped>
.stat-card {
  background: var(--nm-card-bg);
  border: none;
  border-radius: var(--radius-lg);
  padding: 1.65rem 1.75rem;
  box-shadow: var(--nm-card-shadow);
}
.stat-label {
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 0.45rem;
}
.stat-value {
  font-size: 1.6rem;
  font-weight: 680;
  color: var(--ink-primary);
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}
.status-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--ok);
  display: inline-block;
  margin-right: 0.25rem;
}

.card-title {
  font-size: 0.88rem;
  font-weight: 650;
  color: var(--ink-primary);
  margin-bottom: 0.85rem;
  padding-bottom: 0.65rem;
  border-bottom: 2px solid transparent;
  border-image: linear-gradient(to right, transparent, var(--nm-dark), transparent) 1;
}

.list-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.55rem 0;
  border-bottom: 1px solid var(--paper-border);
}
.list-row:last-child { border-bottom: none; }
.list-row-name { font-size: 0.85rem; font-weight: 500; }

.protocol-tag {
  font-family: var(--font-mono);
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  color: var(--ink-muted);
  margin-right: 0.4rem;
}
</style>
