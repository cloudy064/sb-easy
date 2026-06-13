<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.monitor.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.monitor.desc') }}</p>
      </div>
      <span class="badge" :class="connected ? 'badge-green' : 'badge-gray'">
        {{ connected ? 'Live' : 'Disconnected' }}
      </span>
    </div>

    <!-- Traffic + memory stat row -->
    <div class="grid-4 mb-6">
      <div class="stat-card">
        <div class="stat-label">Download</div>
        <div class="stat-value" style="color:var(--ok)">{{ formatRate(traffic.down) }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Upload</div>
        <div class="stat-value" style="color:var(--info)">{{ formatRate(traffic.up) }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Memory</div>
        <div class="stat-value">{{ formatBytes(memory) }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Connections</div>
        <div class="stat-value">{{ connections.length }}</div>
      </div>
    </div>

    <!-- Traffic sparkline -->
    <div class="card mb-6">
      <h3 class="card-title">Throughput</h3>
      <svg class="spark" viewBox="0 0 600 120" preserveAspectRatio="none">
        <polyline :points="sparkPoints(downHistory)" fill="none" stroke="var(--ok)" stroke-width="2" />
        <polyline :points="sparkPoints(upHistory)" fill="none" stroke="var(--info)" stroke-width="2" />
      </svg>
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
        <div v-for="c in filteredConns" :key="c.id" class="conn-row">
          <span class="truncate" :title="connHost(c)">{{ connHost(c) }}</span>
          <span class="truncate text-muted">{{ c.rule }}</span>
          <span class="truncate text-muted">{{ (c.chains || []).slice().reverse().join(' → ') }}</span>
          <span class="ta-r font-mono">{{ formatBytes(c.download) }}</span>
          <span class="ta-r font-mono">{{ formatBytes(c.upload) }}</span>
          <button class="btn-ghost btn-xs" @click="closeOne(c.id)">✕</button>
        </div>
      </div>
    </div>

    <!-- Logs -->
    <div class="card">
      <div class="flex-between mb-4">
        <h3 class="card-title" style="margin:0;border:none;padding:0">Logs</h3>
        <div class="flex-center gap-3">
          <select v-model="logLevel" @change="restartLogs" style="max-width:130px" class="text-sm">
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="error">error</option>
            <option value="debug">debug</option>
          </select>
          <button class="btn-ghost btn-sm" @click="logs = []">Clear</button>
        </div>
      </div>
      <div class="log-box" ref="logBox">
        <div v-for="(l, i) in logs" :key="i" class="log-line">
          <span class="log-type" :class="'lvl-' + l.type">{{ l.type }}</span>
          <span>{{ l.payload }}</span>
        </div>
        <div v-if="!logs.length" class="text-sm text-muted">Waiting for log output…</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
const { t } = useI18n()
import { ref, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import client from '../api/client'
import { openStream, formatBytes, formatRate } from '../api/realtime'
import type { Connection, LogLine } from '../types'

const traffic = ref({ up: 0, down: 0 })
const memory = ref(0)
const connections = ref<Connection[]>([])
const logs = ref<LogLine[]>([])
const filter = ref('')
const logLevel = ref('info')
const logBox = ref<HTMLElement | null>(null)

const downHistory = ref<number[]>([])
const upHistory = ref<number[]>([])
const MAX_POINTS = 60

let sockets: WebSocket[] = []
let logSocket: WebSocket | null = null
const connected = ref(false)

const filteredConns = computed(() => {
  const f = filter.value.toLowerCase()
  if (!f) return connections.value
  return connections.value.filter((c) => {
    const hay = `${connHost(c)} ${c.rule} ${(c.chains || []).join(' ')}`.toLowerCase()
    return hay.includes(f)
  })
})

function connHost(c: Connection): string {
  const m = c.metadata || ({} as Connection['metadata'])
  const host = m.host || m.destinationIP || '?'
  return m.destinationPort ? `${host}:${m.destinationPort}` : host
}

function pushHistory(arr: { value: number[] }, v: number) {
  arr.value.push(v)
  if (arr.value.length > MAX_POINTS) arr.value.shift()
}

function sparkPoints(data: number[]): string {
  if (!data.length) return ''
  const max = Math.max(...data, 1)
  const w = 600, h = 120
  return data
    .map((v, i) => {
      const x = (i / (MAX_POINTS - 1)) * w
      const y = h - (v / max) * (h - 8) - 4
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')
}

function startStreams() {
  const trafficWs = openStream('traffic', (d) => {
    traffic.value = { up: d.up || 0, down: d.down || 0 }
    pushHistory(downHistory, d.down || 0)
    pushHistory(upHistory, d.up || 0)
    connected.value = true
  })
  const memWs = openStream('memory', (d) => { memory.value = d.inuse || 0 })
  const connWs = openStream('connections', (d) => {
    connections.value = d.connections || []
  })
  if (trafficWs) trafficWs.onclose = () => (connected.value = false)
  sockets = [trafficWs, memWs, connWs].filter(Boolean) as WebSocket[]
  startLogs()
}

function startLogs() {
  logSocket = openStream('logs', async (d) => {
    logs.value.push(d as LogLine)
    if (logs.value.length > 500) logs.value.splice(0, logs.value.length - 500)
    await nextTick()
    if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight
  }, { level: logLevel.value })
}

function restartLogs() {
  logSocket?.close()
  logs.value = []
  startLogs()
}

async function closeOne(id: string) {
  try {
    await client.delete(`/sing-box/connections/${id}`)
    connections.value = connections.value.filter((c) => c.id !== id)
  } catch {}
}
async function closeAll() {
  try {
    await client.delete('/sing-box/connections')
    connections.value = []
  } catch {}
}

onMounted(startStreams)
onBeforeUnmount(() => {
  sockets.forEach((s) => s.close())
  logSocket?.close()
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
.stat-value { font-size: 1.4rem; font-weight: 680; color: var(--ink-primary); }
.card-title {
  font-size: 0.88rem; font-weight: 650; color: var(--ink-primary);
  margin-bottom: 0.85rem; padding-bottom: 0.65rem; border-bottom: 1px solid var(--paper-border);
}
.spark {
  width: 100%; height: 120px; display: block;
  background: var(--paper-bg); border-radius: var(--radius-sm);
  border: 1px solid var(--paper-border); margin-bottom: 0.6rem;
}
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 0.3rem; }

.conn-table { font-size: 0.8rem; }
.conn-row {
  display: grid;
  grid-template-columns: 2fr 1.2fr 2fr 0.9fr 0.9fr 32px;
  gap: 0.75rem; align-items: center;
  padding: 0.4rem 0; border-bottom: 1px solid var(--paper-border);
}
.conn-head { font-weight: 600; color: var(--ink-muted); text-transform: uppercase; font-size: 0.65rem; letter-spacing: 0.04em; }
.ta-r { text-align: right; }

.log-box {
  height: 320px; overflow-y: auto;
  background: #1c1a17; border-radius: var(--radius-sm);
  padding: 0.75rem 1rem; font-family: var(--font-mono); font-size: 0.72rem; line-height: 1.7;
}
.log-line { color: #d8d0c4; white-space: pre-wrap; word-break: break-all; }
.log-type {
  display: inline-block; min-width: 58px; margin-right: 0.5rem;
  font-weight: 700; text-transform: uppercase; font-size: 0.62rem;
}
.lvl-info { color: #7fa86b; }
.lvl-warning { color: #d8a657; }
.lvl-error { color: #e07a6c; }
.lvl-debug { color: #7c9cb5; }
.log-box .text-muted { color: #8a8278; }
</style>
