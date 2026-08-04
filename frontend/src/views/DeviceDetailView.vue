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

    <!-- DOMAIN ROUTING (READ ONLY) -->
    <div v-else-if="tab === 'domains'">
      <div class="domain-note mb-3">
        <div>
          <strong>{{ t('device.domains.title') }}</strong>
          <p>{{ t('device.domains.hint') }}</p>
        </div>
        <span class="badge badge-gray">{{ t('device.domains.readonly') }}</span>
      </div>
      <div class="domain-summary mb-3">
        <div class="card domain-stat"><span>{{ t('device.domains.unique') }}</span><strong>{{ uniqueDomainCount }}</strong></div>
        <div class="card domain-stat"><span>{{ t('device.domains.connections') }}</span><strong>{{ totalDomainConnections }}</strong></div>
        <div class="card domain-stat" :class="{ attention: mixedDomainCount > 0 }"><span>{{ t('device.domains.mixed') }}</span><strong>{{ mixedDomainCount }}</strong></div>
      </div>
      <div class="flex-between mb-3 domain-toolbar">
        <input v-model.trim="domainSearch" class="domain-search" type="search" :placeholder="t('device.domains.search')" />
        <span class="text-xs text-muted">{{ t('device.tel.updated') }} {{ ago(telAt) }}</span>
      </div>
      <div v-if="!domainStats.length" class="empty-state">
        <span class="empty-icon">··</span><p>{{ t('device.domains.empty') }}</p>
      </div>
      <div v-else class="card domain-table-card">
        <div class="domain-table-wrap">
          <div class="domain-row domain-head">
            <span>{{ t('device.domains.domain') }}</span><span>{{ t('device.domains.route') }}</span>
            <span class="num">{{ t('device.domains.count') }}</span><span class="num">↓</span><span class="num">↑</span>
            <span>{{ t('device.domains.rule') }}</span><span>{{ t('device.domains.last') }}</span>
          </div>
          <div v-for="(stat, index) in visibleDomainStats" :key="`${stat.domain}-${routeFingerprint(stat)}-${index}`" class="domain-row">
            <span class="domain-name" :title="stat.domain">
              <span class="truncate">{{ stat.domain }}</span>
              <span v-if="domainRouteCount(stat.domain) > 1" class="badge badge-yellow">{{ t('device.domains.mixed.badge') }}</span>
            </span>
            <span class="route-path">
              <span class="badge" :class="routeBadgeClass(stat)">{{ routeKind(stat) }}</span>
              <span class="truncate text-xs" :title="routePath(stat)">{{ routePath(stat) }}</span>
            </span>
            <span class="num domain-count">{{ stat.connection_count }}</span>
            <span class="num">{{ bytes(stat.downlink_total) }}</span>
            <span class="num">{{ bytes(stat.uplink_total) }}</span>
            <span class="truncate text-xs" :title="stat.rule || '—'">{{ stat.rule || '—' }}</span>
            <span class="text-xs text-muted">{{ agoMillis(stat.last_seen) }}</span>
          </div>
          <p v-if="!visibleDomainStats.length" class="text-sm text-muted domain-no-match">{{ t('device.domains.nomatch') }}</p>
        </div>
      </div>
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

    <!-- DIAGNOSTIC REPORTS -->
    <div v-else-if="tab === 'diagnostics'">
      <div class="flex-between mb-3">
        <span class="text-xs text-muted">{{ t('device.diag.hint') }}</span>
        <button class="btn-secondary btn-sm" @click="loadDiagnostics">{{ t('action.refresh') }}</button>
      </div>
      <div v-if="!diagnosticReports.length" class="empty-state">
        <span class="empty-icon">··</span><p>{{ t('device.diag.none') }}</p>
      </div>
      <template v-else>
        <select v-model="selectedDiagnosticId" class="diag-select mb-3">
          <option v-for="report in diagnosticReports" :key="report.report_id" :value="report.report_id">
            {{ report.created_at }} · App {{ report.app_version || '—' }} · {{ report.report_id.slice(0, 8) }}
          </option>
        </select>
        <div v-if="selectedDiagnostic" class="card diag-card">
          <div class="flex-between mb-3">
            <div>
              <h3 class="section-title">{{ t('device.diag.report') }} {{ selectedDiagnostic.report_id.slice(0, 8) }}</h3>
              <span class="text-xs text-muted">{{ selectedDiagnostic.created_at }}</span>
            </div>
            <span class="badge badge-blue">{{ selectedDiagnostic.vpn?.phase || 'UNKNOWN' }}</span>
          </div>
          <div class="diag-summary">
            <div><span>App / Core</span><strong>{{ selectedDiagnostic.app_version || '—' }} / {{ selectedDiagnostic.core_version || '—' }}</strong></div>
            <div><span>Device</span><strong>{{ selectedDiagnostic.device?.manufacturer || '' }} {{ selectedDiagnostic.device?.model || '—' }}</strong></div>
            <div><span>Profile</span><strong>{{ selectedDiagnostic.config?.profile_name || '—' }}</strong></div>
            <div><span>Logs / Connections</span><strong>{{ selectedDiagnostic.logs?.length || 0 }} / {{ selectedDiagnostic.connection_count || 0 }}</strong></div>
          </div>
          <h4 class="diag-heading">{{ t('device.diag.network') }}</h4>
          <pre class="diag-json">{{ JSON.stringify(selectedDiagnostic.network || {}, null, 2) }}</pre>
          <h4 class="diag-heading">{{ t('device.diag.logs') }}</h4>
          <div class="log-box diag-log-box">
            <div v-for="(line, index) in selectedDiagnostic.logs || []" :key="index" class="log-line">{{ line }}</div>
          </div>
        </div>
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
import { serverTimestampAgeMs } from '../api/time'
import type { Host } from '../types'

const { t } = useI18n()
const route = useRoute()
const hostsStore = useHostsStore()

const id = computed(() => String(route.params.id || ''))
const tab = ref<'config' | 'monitor' | 'domains' | 'logs' | 'diagnostics'>('config')
const tabs = computed(() => [
  { key: 'config' as const, label: t('device.tab.config') },
  { key: 'monitor' as const, label: t('device.tab.monitor') },
  { key: 'domains' as const, label: t('device.tab.domains') },
  { key: 'logs' as const, label: t('device.tab.logs') },
  { key: 'diagnostics' as const, label: t('device.tab.diagnostics') },
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
const domainSearch = ref('')
const domainStats = computed<any[]>(() => Array.isArray(tel.value?.domain_stats) ? tel.value.domain_stats : [])
const domainRoutes = computed(() => {
  const routes = new Map<string, Set<string>>()
  domainStats.value.forEach((stat) => {
    const domain = String(stat?.domain || '')
    if (!routes.has(domain)) routes.set(domain, new Set())
    routes.get(domain)?.add(routeFingerprint(stat))
  })
  return routes
})
const uniqueDomainCount = computed(() => domainRoutes.value.size)
const mixedDomainCount = computed(() => [...domainRoutes.value.values()].filter((routes) => routes.size > 1).length)
const totalDomainConnections = computed(() => domainStats.value.reduce((total, stat) => total + Number(stat?.connection_count || 0), 0))
const visibleDomainStats = computed(() => {
  const query = domainSearch.value.toLocaleLowerCase()
  return domainStats.value
    .filter((stat) => !query || [stat.domain, stat.outbound, stat.rule, ...(stat.chain || [])].some((value) => String(value || '').toLocaleLowerCase().includes(query)))
    .sort((left, right) => Number(right.connection_count || 0) - Number(left.connection_count || 0) || Number(right.downlink_total || 0) + Number(right.uplink_total || 0) - Number(left.downlink_total || 0) - Number(left.uplink_total || 0))
})
const diagnosticReports = ref<any[]>([])
const selectedDiagnosticId = ref('')
const selectedDiagnostic = computed(() =>
  diagnosticReports.value.find((report) => report.report_id === selectedDiagnosticId.value) || diagnosticReports.value[0] || null,
)
let poll: ReturnType<typeof setInterval> | null = null

onMounted(async () => {
  if (!hostsStore.hosts.length) await hostsStore.fetchHosts()
  host.value = hostsStore.hosts.find((h) => h.id === id.value) || null
  await loadConfig()
  startPoll()
})
onBeforeUnmount(() => { if (poll) clearInterval(poll) })

watch(tab, (value) => {
  if (value === 'monitor' || value === 'domains' || value === 'logs') refreshTel()
  if (value === 'diagnostics') loadDiagnostics()
})

async function loadConfig() {
  try { const { data } = await client.get(`/hosts/${id.value}/config`); config.value = data } catch { config.value = { error: 'failed to render config' } }
}
function startPoll() {
  refreshTel()
  poll = setInterval(() => { if (tab.value === 'monitor' || tab.value === 'domains' || tab.value === 'logs') refreshTel() }, 3000)
}
async function refreshTel() {
  try { const { data } = await client.get(`/hosts/${id.value}/telemetry`); tel.value = data || {} } catch { /* keep last */ }
}
async function loadDiagnostics() {
  try {
    const { data } = await client.get(`/hosts/${id.value}/diagnostics`)
    diagnosticReports.value = Array.isArray(data) ? data : []
    if (!diagnosticReports.value.some((report) => report.report_id === selectedDiagnosticId.value)) {
      selectedDiagnosticId.value = diagnosticReports.value[0]?.report_id || ''
    }
  } catch { diagnosticReports.value = [] }
}

function rate(bps: number) { return formatRate(bps || 0) }
function bytes(b: number) { return formatBytes(b || 0) }
function routeFingerprint(stat: any) { return `${stat?.outbound || ''}\u0000${(stat?.chain || []).join('\u0000')}` }
function domainRouteCount(domain: string) { return domainRoutes.value.get(domain)?.size || 0 }
function routePath(stat: any) {
  const chain = Array.isArray(stat?.chain) ? stat.chain.filter(Boolean) : []
  return chain.length ? chain.join(' → ') : (stat?.outbound || t('device.domains.unknown'))
}
function routeKind(stat: any) {
  const value = [stat?.outbound, stat?.outbound_type, ...(stat?.chain || [])].join(' ').toLocaleLowerCase()
  if (value.includes('direct')) return 'DIRECT'
  if (value.includes('block') || value.includes('reject')) return 'BLOCK'
  return value.trim() ? 'PROXY' : 'UNKNOWN'
}
function routeBadgeClass(stat: any) {
  const kind = routeKind(stat)
  return kind === 'DIRECT' ? 'badge-green' : kind === 'BLOCK' ? 'badge-red' : kind === 'PROXY' ? 'badge-blue' : 'badge-gray'
}
function agoMillis(value: number) {
  const timestamp = Number(value || 0)
  if (!timestamp) return '—'
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000))
  return seconds < 60 ? `${seconds}s ago` : seconds < 3600 ? `${Math.round(seconds / 60)}m ago` : `${Math.round(seconds / 3600)}h ago`
}
function ago(iso: string) {
  if (!iso) return ''
  const age = serverTimestampAgeMs(iso)
  if (age === null) return ''
  const s = Math.round(age / 1000)
  return s < 60 ? `${s}s ago` : `${Math.round(s / 60)}m ago`
}
const online = computed(() => {
  if (isSelf.value) return true
  if (!host.value?.last_seen) return false
  const age = serverTimestampAgeMs(host.value.last_seen)
  return age !== null && age < 60_000
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

.domain-note { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; padding: 0.85rem 1rem; border: 1px solid var(--paper-border); border-radius: var(--radius-sm); background: var(--paper-bg); }
.domain-note strong { font-size: 0.86rem; color: var(--ink-primary); }
.domain-note p { margin: 0.25rem 0 0; max-width: 850px; color: var(--ink-secondary); font-size: 0.74rem; line-height: 1.55; }
.domain-summary { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.8rem; }
.domain-stat { display: flex; flex-direction: column; gap: 0.25rem; padding: 0.85rem 1rem; }
.domain-stat span { color: var(--ink-muted); font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.04em; }
.domain-stat strong { font: 700 1.25rem var(--font-mono); color: var(--ink-primary); }
.domain-stat.attention strong { color: var(--warn); }
.domain-search { width: min(420px, 100%); }
.domain-table-card { padding: 0.35rem 0.7rem 0.65rem; }
.domain-table-wrap { overflow-x: auto; }
.domain-row { min-width: 1000px; display: grid; grid-template-columns: 1.7fr 1.65fr 0.5fr 0.65fr 0.65fr 1.5fr 0.6fr; gap: 0.75rem; align-items: center; padding: 0.62rem 0.4rem; border-bottom: 1px solid var(--paper-border); font-size: 0.8rem; }
.domain-head { color: var(--ink-muted); font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }
.domain-name, .route-path { min-width: 0; display: flex; align-items: center; gap: 0.4rem; }
.route-path .badge { flex: none; }
.domain-row .num { text-align: right; font: 0.72rem var(--font-mono); }
.domain-count { color: var(--ink-primary); font-weight: 650 !important; }
.domain-no-match { padding: 1rem 0.4rem; }

.log-box { height: 62vh; min-height: 320px; overflow-y: auto; background: #1c1a17; border-radius: var(--radius-sm); padding: 0.85rem 1.1rem; font-family: var(--font-mono); font-size: 0.74rem; line-height: 1.7; }
.log-line { color: #d8d0c4; white-space: pre-wrap; word-break: break-all; }
.diag-select { max-width: 560px; }
.diag-card { padding: 1.5rem; }
.diag-summary { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.7rem; }
.diag-summary div { display: flex; flex-direction: column; padding: 0.7rem 0.8rem; border-radius: var(--radius-sm); background: var(--paper-bg); }
.diag-summary span { color: var(--ink-muted); font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.04em; }
.diag-summary strong { color: var(--ink-primary); font-size: 0.82rem; margin-top: 0.2rem; word-break: break-word; }
.diag-heading { font-size: 0.78rem; color: var(--ink-secondary); margin: 1.1rem 0 0.45rem; text-transform: uppercase; letter-spacing: 0.04em; }
.diag-json { max-height: 260px; overflow: auto; padding: 0.8rem 1rem; border-radius: var(--radius-sm); background: #1c1a17; color: #d8d0c4; font: 0.72rem/1.55 var(--font-mono); white-space: pre-wrap; }
.diag-log-box { height: 52vh; }
@media (max-width: 680px) {
  .diag-summary, .domain-summary { grid-template-columns: 1fr; }
  .domain-note, .domain-toolbar { align-items: stretch; flex-direction: column; }
}
</style>
