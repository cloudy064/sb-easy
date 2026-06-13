<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.monitor.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.monitor.desc') }}</p>
      </div>
      <div class="flex-center gap-3">
        <HostSelect @change="onHostChange" />
        <span class="badge" :class="connected ? 'badge-green' : 'badge-gray'">
          {{ connected ? 'Live' : 'Disconnected' }}
        </span>
      </div>
    </div>

    <!-- Traffic + memory stat row -->
    <div class="grid-4 mb-6">
      <div class="stat-card">
        <div class="stat-label">Download</div>
        <!-- Rate: show the raw per-second sample (no easing) so the figure is accurate. -->
        <div class="stat-value" style="color:var(--ok)">{{ formatRate(traffic.down) }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Upload</div>
        <div class="stat-value" style="color:var(--info)">{{ formatRate(traffic.up) }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Memory</div>
        <div class="stat-value"><AnimatedNumber :value="memory" :format="formatBytes" /></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Connections</div>
        <div class="stat-value"><AnimatedNumber :value="activeCount" :format="formatCount" /></div>
      </div>
    </div>

    <!-- Throughput chart -->
    <div class="card mb-6">
      <h3 class="card-title">Throughput</h3>
      <SparkChart :down="traffic.down" :up="traffic.up" :seq="trafficSeq" />
      <div class="flex-center gap-4 text-xs text-muted">
        <span><span class="dot" style="background:var(--ok)"></span> Download</span>
        <span><span class="dot" style="background:var(--info)"></span> Upload</span>
      </div>
    </div>

    <!-- Connections -->
    <div class="card mb-6">
      <div class="flex-between mb-4">
        <h3 class="card-title" style="margin:0;border:none;padding:0">Active Connections</h3>
        <div class="flex-center gap-3">
          <input v-model="filter" placeholder="Filter host / rule / chain…" style="max-width:240px" class="text-sm" />
          <button class="btn-danger btn-sm" @click="closeAll" :disabled="!connections.length">Close all</button>
        </div>
      </div>
      <div v-if="!filteredConns.length" class="text-sm text-muted" style="padding:1rem 0">No active connections.</div>
      <div v-else class="conn-table">
        <div class="conn-row conn-head">
          <span>Host</span><span>Rule</span><span>Chain</span><span class="ta-r">↓</span><span class="ta-r">↑</span><span></span>
        </div>
        <TransitionGroup tag="div" name="conn" class="conn-body">
          <div v-for="c in filteredConns" :key="c.id" class="conn-row" :class="{ closing: c.closing }">
            <span class="truncate" :title="connHost(c)">
              <span v-if="c.closing" class="closed-tag">closed</span>{{ connHost(c) }}
            </span>
            <span class="truncate text-muted">{{ c.rule }}</span>
            <span class="truncate text-muted">{{ (c.chains || []).slice().reverse().join(' → ') }}</span>
            <span class="ta-r font-mono">{{ formatBytes(c.download) }}</span>
            <span class="ta-r font-mono">{{ formatBytes(c.upload) }}</span>
            <button class="btn-ghost btn-xs" @click="closeOne(c.id)">✕</button>
          </div>
        </TransitionGroup>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import client from '../api/client'
import { openStream, formatBytes, formatRate } from '../api/realtime'
import AnimatedNumber from '../components/AnimatedNumber.vue'
import SparkChart from '../components/SparkChart.vue'
import HostSelect from '../components/HostSelect.vue'
import { useHostTarget } from '../composables/hostTarget'
import type { Connection } from '../types'

const { t } = useI18n()
const { selectedHost, reqParams } = useHostTarget()

interface ConnRow extends Connection { closing?: boolean }

const CLOSE_GRACE_MS = 3000

const traffic = ref({ up: 0, down: 0 })
const trafficSeq = ref(0)
const memory = ref(0)
const connections = ref<ConnRow[]>([])
// Pending removal timers for connections in their grace period.
const removeTimers = new Map<string, ReturnType<typeof setTimeout>>()
const filter = ref('')
const connected = ref(false)

let sockets: WebSocket[] = []

const formatCount = (n: number) => String(Math.round(n))

// Stable order (by id) so the list doesn't reshuffle each tick; only the byte
// figures change in place while TransitionGroup animates add/remove/move.
const filteredConns = computed(() => {
  const f = filter.value.toLowerCase()
  const list = f
    ? connections.value.filter((c) => {
        const hay = `${connHost(c)} ${c.rule} ${(c.chains || []).join(' ')}`.toLowerCase()
        return hay.includes(f)
      })
    : connections.value
  return [...list].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
})

function connHost(c: Connection): string {
  const m = c.metadata || ({} as Connection['metadata'])
  const host = m.host || m.destinationIP || '?'
  return m.destinationPort ? `${host}:${m.destinationPort}` : host
}

// Count of live (non-closing) connections, for the stat card.
const activeCount = computed(() => connections.value.reduce((n, c) => n + (c.closing ? 0 : 1), 0))

// Merge a fresh snapshot into the maintained list. Connections that vanished
// are kept and flagged `closing` (shown red) for a grace period before removal,
// so the user has time to notice; a connection that reappears is un-flagged.
function mergeConnections(list: Connection[]) {
  const incoming = new Map(list.map((c) => [c.id, c]))
  const seen = new Set<string>()
  const next: ConnRow[] = []

  for (const existing of connections.value) {
    const fresh = incoming.get(existing.id)
    if (fresh) {
      cancelRemoval(existing.id)
      next.push({ ...fresh, closing: false })
    } else if (existing.closing) {
      next.push(existing) // already counting down; leave its timer running
    } else {
      scheduleRemoval(existing.id)
      next.push({ ...existing, closing: true })
    }
    seen.add(existing.id)
  }
  for (const c of list) {
    if (!seen.has(c.id)) next.push({ ...c, closing: false })
  }
  connections.value = next
}

function scheduleRemoval(id: string) {
  if (removeTimers.has(id)) return
  const t = setTimeout(() => {
    connections.value = connections.value.filter((c) => c.id !== id)
    removeTimers.delete(id)
  }, CLOSE_GRACE_MS)
  removeTimers.set(id, t)
}

function cancelRemoval(id: string) {
  const t = removeTimers.get(id)
  if (t !== undefined) {
    clearTimeout(t)
    removeTimers.delete(id)
  }
}

function clearAllTimers() {
  removeTimers.forEach((t) => clearTimeout(t))
  removeTimers.clear()
}

function startStreams() {
  const host = selectedHost.value
  const trafficWs = openStream('traffic', (d) => {
    // Values may arrive as strings; coerce so downstream math stays numeric.
    traffic.value = { up: Number(d.up) || 0, down: Number(d.down) || 0 }
    trafficSeq.value++
    connected.value = true
  }, { host })
  const memWs = openStream('memory', (d) => { memory.value = Number(d.inuse) || 0 }, { host })
  const connWs = openStream('connections', (d) => {
    mergeConnections(d.connections || [])
  }, { host })
  if (trafficWs) trafficWs.onclose = () => (connected.value = false)
  sockets = [trafficWs, memWs, connWs].filter(Boolean) as WebSocket[]
}

function stopStreams() {
  sockets.forEach((s) => s.close())
  sockets = []
}

// Switching host: tear down current streams, reset view, reconnect to the new target.
function onHostChange() {
  stopStreams()
  clearAllTimers()
  connections.value = []
  traffic.value = { up: 0, down: 0 }
  memory.value = 0
  connected.value = false
  startStreams()
}

async function closeOne(id: string) {
  try {
    await client.delete(`/sing-box/connections/${id}`, { params: reqParams.value })
    cancelRemoval(id)
    connections.value = connections.value.filter((c) => c.id !== id)
  } catch {}
}
async function closeAll() {
  try {
    await client.delete('/sing-box/connections', { params: reqParams.value })
    clearAllTimers()
    connections.value = []
  } catch {}
}

onMounted(startStreams)
onBeforeUnmount(() => {
  sockets.forEach((s) => s.close())
  clearAllTimers()
})
</script>

<style scoped>
.stat-card {
  background: var(--paper-surface);
  border: 1px solid var(--paper-border);
  border-radius: var(--radius-lg);
  padding: 1.25rem 1.5rem;
  box-shadow: var(--paper-shadow-card);
}
.stat-label {
  font-size: 0.72rem; font-weight: 600; color: var(--ink-muted);
  text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.4rem;
}
.stat-value { font-size: 1.4rem; font-weight: 680; color: var(--ink-primary); font-variant-numeric: tabular-nums; }
.card-title {
  font-size: 0.88rem; font-weight: 650; color: var(--ink-primary);
  margin-bottom: 0.85rem; padding-bottom: 0.65rem; border-bottom: 1px solid var(--paper-border);
}
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 0.3rem; }

.conn-table { font-size: 0.8rem; }
.conn-body { position: relative; }
.conn-row {
  display: grid;
  grid-template-columns: 2fr 1.2fr 2fr 0.9fr 0.9fr 32px;
  gap: 0.75rem; align-items: center;
  padding: 0.4rem 0; border-bottom: 1px solid var(--paper-border);
}
.conn-row .font-mono { font-variant-numeric: tabular-nums; }
.conn-head { font-weight: 600; color: var(--ink-muted); text-transform: uppercase; font-size: 0.65rem; letter-spacing: 0.04em; }
.ta-r { text-align: right; }

/* A connection that vanished from the stream: held red for a grace period
   before removal so the user can notice it dropped. */
.conn-row.closing { color: var(--bad); background: var(--bad-bg); }
.conn-row.closing .text-muted { color: var(--bad); opacity: 0.7; }
.closed-tag {
  display: inline-block;
  font-size: 0.58rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.04em;
  background: var(--bad); color: #fff;
  padding: 0 0.3rem; border-radius: 3px; margin-right: 0.35rem;
  vertical-align: middle;
}

/* Smooth add / remove / reorder of connection rows. */
.conn-move { transition: transform 0.3s ease; }
.conn-enter-active { transition: opacity 0.3s ease, transform 0.3s ease; }
.conn-leave-active { transition: opacity 0.25s ease, transform 0.25s ease; position: absolute; width: 100%; }
.conn-enter-from { opacity: 0; transform: translateY(-6px); }
.conn-leave-to { opacity: 0; transform: translateY(6px); }
</style>
