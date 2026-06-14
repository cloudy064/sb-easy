<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.logs.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.logs.desc') }}</p>
      </div>
      <div class="flex-center gap-3">
        <HostSelect @change="restartLogs" />
        <span class="badge" :class="connected ? 'badge-green' : 'badge-gray'">
          {{ connected ? 'Live' : 'Disconnected' }}
        </span>
      </div>
    </div>

    <div class="card">
      <div class="flex-between mb-4">
        <div class="flex-center gap-3">
          <select v-model="logLevel" @change="restartLogs" style="max-width:140px" class="text-sm">
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="error">error</option>
            <option value="debug">debug</option>
          </select>
          <button class="btn-ghost btn-sm" @click="clearLogs">Clear</button>
        </div>
        <span class="text-xs text-muted">{{ logs.length }} lines</span>
      </div>
      <div class="log-box" ref="logBox">
        <TransitionGroup name="log">
          <div v-for="l in logs" :key="l.id" class="log-line">
            <span class="log-type" :class="'lvl-' + l.type">{{ l.type }}</span>
            <span>{{ l.payload }}</span>
          </div>
        </TransitionGroup>
        <div v-if="!logs.length" class="text-sm text-muted">Waiting for log output…</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
import { ref, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { openStream } from '../api/realtime'
import HostSelect from '../components/HostSelect.vue'
import { useHostTarget } from '../composables/hostTarget'

const { t } = useI18n()
const { selectedHost } = useHostTarget()

interface LogEntry { id: number; type: string; payload: string }

const logs = ref<LogEntry[]>([])
const logLevel = ref('info')
const logBox = ref<HTMLElement | null>(null)
const connected = ref(false)
let logSocket: WebSocket | null = null
let logSeq = 0

function startLogs() {
  logSocket = openStream('logs', async (d) => {
    const atBottom = isScrolledToBottom()
    logs.value.push({ id: logSeq++, type: d.type || 'info', payload: d.payload ?? String(d) })
    if (logs.value.length > 1000) logs.value.splice(0, logs.value.length - 1000)
    await nextTick()
    if (atBottom && logBox.value) {
      logBox.value.scrollTo({ top: logBox.value.scrollHeight, behavior: 'smooth' })
    }
  }, { level: logLevel.value, host: selectedHost.value })
  if (logSocket) {
    logSocket.onopen = () => (connected.value = true)
    logSocket.onclose = () => (connected.value = false)
  }
}

function isScrolledToBottom(): boolean {
  const el = logBox.value
  if (!el) return true
  return el.scrollHeight - el.scrollTop - el.clientHeight < 40
}

function restartLogs() {
  logSocket?.close()
  logs.value = []
  startLogs()
}
function clearLogs() { logs.value = [] }

onMounted(startLogs)
onBeforeUnmount(() => logSocket?.close())
</script>

<style scoped>
.log-box {
  height: 65vh; min-height: 360px;
  overflow-y: auto;
  background: #1c1a17; border-radius: var(--radius-sm);
  padding: 0.85rem 1.1rem; font-family: var(--font-mono); font-size: 0.74rem; line-height: 1.7;
}
.log-line { color: #d8d0c4; white-space: pre-wrap; word-break: break-all; }
.log-enter-active { transition: opacity 0.25s ease, transform 0.25s ease; }
.log-enter-from { opacity: 0; transform: translateY(4px); }
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
