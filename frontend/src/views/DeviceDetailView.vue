<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <router-link to="/devices" class="back-link">← {{ t('nav.devices') }}</router-link>
        <h2 style="margin-top:.3rem">
          <span class="online-dot" :class="online ? 'on' : 'off'"></span>
          {{ host?.name || id }}
          <span v-if="isSelf" class="kind-badge kind-self">SELF</span>
        </h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ host?.wg_address || '' }} · {{ statusText }}</p>
      </div>
      <div class="flex-center gap-2" v-if="host">
        <button class="btn-ghost btn-sm" @click="showManage = true">{{ t('hosts.edit') }}</button>
        <button v-if="!isSelf" class="btn-ghost btn-sm" @click="cmd('reload')">{{ t('hosts.reload') }}</button>
        <button v-if="!isSelf" class="btn-ghost btn-sm" @click="cmd('restart')">{{ t('hosts.restart') }}</button>
      </div>
    </div>

    <div class="tabs">
      <button v-for="tb in tabs" :key="tb.key" :class="['tab', { active: tab === tb.key }]" @click="tab = tb.key">{{ tb.label }}</button>
    </div>

    <!-- CONFIG -->
    <div v-if="tab === 'config'">
      <div class="flex-between mb-3">
        <span class="text-xs text-muted">{{ t('device.tab.config.hint') }}</span>
        <div class="flex-center gap-2">
          <button class="btn-secondary btn-sm" @click="copyConfig">{{ copied ? t('action.copied') : t('action.copy') }}</button>
          <button class="btn-primary btn-sm" @click="downloadConfig">Download</button>
        </div>
      </div>
      <div class="card"><pre class="code-pre">{{ configPretty }}</pre></div>
    </div>

    <!-- MONITOR -->
    <div v-else-if="tab === 'monitor'">
      <div v-if="!telAt" class="empty-state"><span class="empty-icon">··</span><p>{{ t('device.tel.waiting') }}</p></div>
      <template v-else>
        <div class="grid-2 mb-4">
          <div class="card stat-card"><span class="stat-k">↓ {{ t('device.mon.down') }}</span><span class="stat-v" style="color:var(--ok)">{{ rate(tel.down) }}</span></div>
          <div class="card stat-card"><span class="stat-k">↑ {{ t('device.mon.up') }}</span><span class="stat-v" style="color:var(--info)">{{ rate(tel.up) }}</span></div>
        </div>
        <div class="card">
          <div class="flex-between mb-3">
            <h3 class="section-title">{{ t('device.mon.conns') }} · {{ tel.conn_count }}</h3>
            <span class="text-xs text-muted">{{ t('device.tel.updated') }} {{ ago(telAt) }}</span>
          </div>
          <div class="conn-table">
            <div class="conn-row conn-head"><span>Host</span><span>Chain</span><span class="num">↓</span><span class="num">↑</span></div>
            <div v-for="(c, i) in conns" :key="c.id || i" class="conn-row">
              <span class="truncate">{{ c.metadata?.host || c.metadata?.destinationIP || '—' }}<span class="text-muted">:{{ c.metadata?.destinationPort }}</span></span>
              <span class="truncate text-xs">{{ (c.chains || []).slice().reverse().join(' → ') }}</span>
              <span class="num">{{ bytes(c.download) }}</span>
              <span class="num">{{ bytes(c.upload) }}</span>
            </div>
            <p v-if="!conns.length" class="text-sm text-muted">{{ t('device.mon.noconns') }}</p>
          </div>
        </div>
      </template>
    </div>

    <!-- LOGS -->
    <div v-else-if="tab === 'logs'">
      <div v-if="!telAt" class="empty-state"><span class="empty-icon">··</span><p>{{ t('device.tel.waiting') }}</p></div>
      <template v-else>
        <div class="flex-between mb-3"><span class="text-xs text-muted">{{ tel.logs?.length || 0 }} lines · {{ t('device.tel.updated') }} {{ ago(telAt) }}</span></div>
        <div class="card"><div class="log-box">
          <div v-for="(l, i) in tel.logs" :key="i" class="log-line">{{ l }}</div>
          <p v-if="!tel.logs?.length" class="text-sm text-muted">{{ t('device.logs.none') }}</p>
        </div></div>
      </template>
    </div>

    <HostManageModal v-if="showManage" :host="host" @close="showManage = false" @saved="onManageSaved" />
    <div v-if="toast" class="toast"><div class="toast-item toast-success">{{ toast }}</div></div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from '../composables/i18n'
import { useHostsStore } from '../stores/hosts'
import HostManageModal from '../components/HostManageModal.vue'
import client from '../api/client'
import { formatRate, formatBytes } from '../api/realtime'
import type { Host } from '../types'

const { t } = useI18n()
const route = useRoute()
const hostsStore = useHostsStore()

const id = computed(() => String(route.params.id || ''))
const tab = ref<'config' | 'monitor' | 'logs'>('config')
const tabs = computed(() => [
  { key: 'config' as const, label: t('device.tab.config') },
  { key: 'monitor' as const, label: t('device.tab.monitor') },
  { key: 'logs' as const, label: t('device.tab.logs') },
])

const host = ref<Host | null>(null)
const isSelf = computed(() => !!host.value?.capabilities?.is_self)
const config = ref<any>(null)
const configPretty = computed(() => (config.value ? JSON.stringify(config.value, null, 2) : ''))
const copied = ref(false)
const showManage = ref(false)
const toast = ref('')

// telemetry
const tel = ref<any>({})
const telAt = computed(() => tel.value?.at || '')
const conns = computed<any[]>(() => Array.isArray(tel.value?.connections) ? tel.value.connections : [])
let poll: ReturnType<typeof setInterval> | null = null

onMounted(async () => {
  if (!hostsStore.hosts.length) await hostsStore.fetchHosts()
  host.value = hostsStore.hosts.find((h) => h.id === id.value) || null
  await loadConfig()
  startPoll()
})
onBeforeUnmount(() => { if (poll) clearInterval(poll) })

watch(tab, (v) => { if (v !== 'config') refreshTel() })

async function loadConfig() {
  try { const { data } = await client.get(`/hosts/${id.value}/config`); config.value = data } catch { config.value = { error: 'failed to render config' } }
}
function startPoll() {
  refreshTel()
  poll = setInterval(() => { if (tab.value !== 'config') refreshTel() }, 3000)
}
async function refreshTel() {
  try { const { data } = await client.get(`/hosts/${id.value}/telemetry`); tel.value = data || {} } catch { /* keep last */ }
}

function rate(bps: number) { return formatRate(bps || 0) }
function bytes(b: number) { return formatBytes(b || 0) }
function ago(iso: string) {
  if (!iso) return ''
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  return s < 60 ? `${s}s ago` : `${Math.round(s / 60)}m ago`
}
const online = computed(() => {
  if (isSelf.value) return true
  if (!host.value?.last_seen) return false
  return Date.now() - new Date(host.value.last_seen).getTime() < 60_000
})
const statusText = computed(() => {
  if (isSelf.value) return t('hosts.status.local')
  return online.value ? t('hosts.status.online') : t('hosts.status.offline')
})

async function copyConfig() { await navigator.clipboard?.writeText(configPretty.value); copied.value = true; setTimeout(() => (copied.value = false), 1500) }
function downloadConfig() {
  const blob = new Blob([configPretty.value], { type: 'application/json' })
  const url = URL.createObjectURL(blob); const a = document.createElement('a')
  a.href = url; a.download = `${(host.value?.name || id.value).replace(/\s+/g, '_')}-config.json`; a.click(); URL.revokeObjectURL(url)
}
async function cmd(command: 'reload' | 'restart') {
  try { await hostsStore.enqueueCommand(id.value, command); notify(t('hosts.cmd.queued')) } catch { notify(t('hosts.cmd.failed')) }
}
async function onManageSaved() { showManage.value = false; await hostsStore.fetchHosts(); host.value = hostsStore.hosts.find((h) => h.id === id.value) || null }
function notify(m: string) { toast.value = m; setTimeout(() => (toast.value = ''), 2200) }
</script>

<style scoped>
.back-link { font-size: 0.78rem; color: var(--ink-muted); text-decoration: none; }
.back-link:hover { color: var(--accent); }
.online-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 0.4rem; vertical-align: middle; }
.online-dot.on { background: var(--ok); box-shadow: 0 0 0 3px var(--ok-bg); }
.online-dot.off { background: #cbc4b8; }
.kind-badge { font-family: var(--font-mono); font-size: 0.55rem; font-weight: 700; padding: 0.1rem 0.38rem; border-radius: 4px; margin-left: 0.4rem; vertical-align: middle; }
.kind-self { background: var(--paper-border); color: var(--ink-secondary); }

.tabs { display: flex; gap: 0.25rem; border-bottom: 1px solid var(--paper-border); margin: 0.5rem 0 1.25rem; }
.tab { background: none; border: none; padding: 0.5rem 0.9rem; font-size: 0.85rem; color: var(--ink-secondary); border-bottom: 2px solid transparent; cursor: pointer; }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }

.code-pre { font-family: var(--font-mono); font-size: 0.72rem; line-height: 1.55; background: #1c1a17; color: #d8d0c4; padding: 1rem 1.25rem; border-radius: var(--radius-sm); overflow: auto; max-height: 68vh; white-space: pre; margin: 0; }
.card { padding: 1.25rem 1.5rem; }
.stat-card { display: flex; flex-direction: column; gap: 0.3rem; }
.stat-k { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--ink-muted); }
.stat-v { font-size: 1.5rem; font-weight: 700; font-family: var(--font-mono); }
.section-title { font-size: 0.95rem; font-weight: 650; margin: 0; }

.conn-table { display: flex; flex-direction: column; }
.conn-row { display: grid; grid-template-columns: 2fr 2fr 0.7fr 0.7fr; gap: 0.6rem; padding: 0.4rem 0.2rem; border-bottom: 1px solid var(--paper-border); font-size: 0.8rem; align-items: center; }
.conn-head { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--ink-muted); font-weight: 600; }
.conn-row .num { font-family: var(--font-mono); text-align: right; font-size: 0.72rem; }

.log-box { height: 62vh; min-height: 320px; overflow-y: auto; background: #1c1a17; border-radius: var(--radius-sm); padding: 0.85rem 1.1rem; font-family: var(--font-mono); font-size: 0.74rem; line-height: 1.7; }
.log-line { color: #d8d0c4; white-space: pre-wrap; word-break: break-all; }
</style>
