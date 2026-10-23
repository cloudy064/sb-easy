<template>
  <div class="operations">
    <div class="page-header flex-between"><div><h2>{{ text('统计与告警', 'Statistics and alerts') }}</h2><p class="text-muted">{{ text('设备状态、最近成功配置与保留的采样记录', 'Device status, last successful configuration and retained samples') }}</p></div><button class="btn-secondary" :disabled="busy" @click="run(load)">{{ text('刷新', 'Refresh') }}</button></div>
    <p v-if="error" role="alert" class="notice error">{{ error }}</p><p v-if="message" role="status" class="notice">{{ message }}</p>
    <section class="card"><div class="flex-between"><h3>{{ text('告警事件', 'Alert events') }}</h3><label><input v-model="activeOnly" type="checkbox" @change="run(loadAlerts)" /> {{ text('只看未恢复', 'Active only') }}</label></div>
      <p class="text-sm text-muted">{{ text('每 30 秒评估一次。确认表示已读；条件消失后结束，再次触发会创建新事件。节点探测超过一小时后显示数据过期。', 'Evaluated every 30 seconds. Acknowledgement marks an event as read; a recurrence creates a new event. Node probes become stale after one hour.') }}</p>
      <p v-if="!alerts.length" class="text-muted">{{ text('没有符合条件的事件', 'No matching events') }}</p>
      <div v-for="alert in alerts" :key="alert.id" class="event"><div><strong>{{ kind(alert.kind) }}</strong><p class="text-sm">{{ resourceName(alert.resource_id) }}</p><p class="text-xs text-muted">{{ when(alert.opened_at) }} <span v-if="alert.resolved_at"> → {{ when(alert.resolved_at) }}</span></p></div><span v-if="alert.resolved_at">{{ text('已结束', 'Ended') }}</span><span v-else-if="alert.acknowledged_at">{{ text('已确认', 'Acknowledged') }}</span><button v-else class="btn-secondary btn-sm" :disabled="busy" @click="run(() => acknowledge(alert.id))">{{ text('确认', 'Acknowledge') }}</button></div>
    </section>
    <section class="card"><h3>{{ text('设备运行版本与配置', 'Device versions and configuration') }}</h3><div class="table-wrap"><table><thead><tr><th>{{ text('设备', 'Device') }}</th><th>{{ text('应用 / 核心', 'App / core') }}</th><th>{{ text('最近上报', 'Last report') }}</th><th>{{ text('最近成功配置', 'Last successful configuration') }}</th><th>{{ text('失败原因', 'Last error') }}</th></tr></thead><tbody><tr v-for="host in hosts" :key="host.host_id"><td><router-link :to="`/devices/${encodeURIComponent(host.host_id)}`">{{ host.name }}</router-link><p class="text-xs">{{ host.online ? text('在线', 'Online') : text('无近期状态', 'No recent status') }}</p></td><td>{{ host.app_version || '—' }} / {{ host.core_version || '—' }}</td><td>{{ when(host.status_at) }}</td><td><code :title="host.applied_etag">{{ host.applied_etag ? host.applied_etag.slice(0, 18) + '…' : '—' }}</code><p class="text-xs">{{ when(host.applied_at) }}</p></td><td class="last-error">{{ host.last_error || '—' }}</td></tr></tbody></table></div>
      <label>{{ text('查看设备历史', 'View device history') }} <select v-model="selectedHost"><option value="" disabled>{{ text('选择设备', 'Select a device') }}</option><option v-for="host in hosts" :key="host.host_id" :value="host.host_id">{{ host.name }}</option></select></label>
    </section>
    <DeviceHistoryPanel v-if="selectedHost" :host-id="selectedHost" />
    <section class="card"><h3>{{ text('保留与告警阈值', 'Retention and alert thresholds') }}</h3><form class="settings" @submit.prevent="run(saveSettings)">
      <label>{{ text('保留天数', 'Retention days') }}<input v-model.number="settings.retention_days" type="number" min="1" max="365" required /></label>
      <label>{{ text('设备未上报秒数', 'Seconds without device status') }}<input v-model.number="settings.offline_seconds" type="number" min="30" max="86400" required /></label>
      <label>{{ text('配置未应用秒数', 'Seconds before configuration drift') }}<input v-model.number="settings.drift_seconds" type="number" min="30" max="86400" required /></label>
      <label>{{ text('节点慢响应毫秒', 'Slow node response in milliseconds') }}<input v-model.number="settings.node_latency_ms" type="number" min="1" max="60000" required /></label>
      <p class="text-sm text-muted">{{ text('缩短保留时间会在下一轮清理中删除更早的采样和已结束事件。', 'Shorter retention deletes older samples and ended events during the next cleanup.') }}</p><button class="btn-primary" :disabled="busy">{{ text('保存', 'Save') }}</button>
    </form></section>
    <section class="card"><h3>Prometheus</h3><p>{{ text('使用独立的只读抓取令牌，通过 HTTPS 访问 /api/metrics。该令牌不能登录面板或控制设备。', 'Use a separate read-only scrape token with HTTPS at /api/metrics. It cannot sign in to the panel or control devices.') }}</p>
      <div class="actions"><button class="btn-primary" :disabled="busy" @click="run(rotateToken)">{{ metricsConfigured ? text('轮换抓取令牌', 'Rotate scrape token') : text('创建抓取令牌', 'Create scrape token') }}</button><button v-if="metricsConfigured" class="btn-danger" :disabled="busy" @click="run(revokeToken)">{{ text('撤销', 'Revoke') }}</button></div>
      <div v-if="scrapeToken"><p>{{ text('令牌仅本次显示。轮换后旧令牌立即失效。', 'This token is shown only now. Rotation immediately invalidates the previous token.') }}</p><code class="token">{{ scrapeToken }}</code><button class="btn-secondary" @click="run(copyToken)">{{ text('复制令牌', 'Copy token') }}</button></div>
      <details><summary>{{ text('抓取配置示例', 'Scrape configuration example') }}</summary><pre>{{ prometheusExample }}</pre></details>
    </section>
  </div>
</template>
<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import client from '../api/client'
import { useI18n } from '../composables/i18n'
import DeviceHistoryPanel from '../components/DeviceHistoryPanel.vue'
const { locale } = useI18n(), text = (zh: string, en: string) => locale.value === 'zh' ? zh : en
interface Host { host_id: string; name: string; online: boolean; status_at: number; app_version: string; core_version: string; applied_etag: string; applied_at: number; last_error: string }
interface Alert { id: number; kind: string; resource_id: string; opened_at: number; resolved_at: number | null; acknowledged_at: number | null }
const hosts = ref<Host[]>([]), alerts = ref<Alert[]>([]), activeOnly = ref(true), selectedHost = ref('')
const busy = ref(false), error = ref(''), message = ref(''), metricsConfigured = ref(false), scrapeToken = ref('')
const settings = ref({ retention_days: 30, offline_seconds: 180, drift_seconds: 300, node_latency_ms: 5000 })
const when = (seconds: number) => seconds ? new Date(seconds * 1000).toLocaleString() : '—'
const resourceName = (id: string) => hosts.value.find(host => host.host_id === id)?.name || id
const kind = (value: string) => ({ device_offline: text('设备未上报', 'Device not reporting'), config_drift: text('配置未应用', 'Configuration not applied'), config_failure: text('配置应用失败', 'Configuration failed'), node_unreachable: text('节点不可达', 'Node unreachable'), node_slow: text('节点响应慢', 'Slow node'), node_probe_stale: text('节点探测数据过期', 'Node probe stale') }[value] || value)
const prometheusExample = `scrape_configs:\n  - job_name: sb-easy\n    scheme: https\n    metrics_path: /api/metrics\n    authorization:\n      type: Bearer\n      credentials_file: /etc/prometheus/sb-easy-token\n    static_configs:\n      - targets: ['${location.host}']`
async function run(action: () => Promise<void>) { if (busy.value) return; busy.value = true; error.value = ''; message.value = ''; try { await action() } catch (e: any) { error.value = e.response?.data?.error || e.message } finally { busy.value = false } }
async function loadAlerts() { alerts.value = (await client.get('/observability/alerts', { params: { active: activeOnly.value ? 1 : 0 } })).data }
async function load() { const [overview] = await Promise.all([client.get('/observability'), loadAlerts()]); hosts.value = overview.data.hosts; if (!selectedHost.value && hosts.value.length) selectedHost.value = hosts.value.find(host => host.host_id !== 'self')?.host_id || hosts.value[0]!.host_id }
async function acknowledge(id: number) { await client.post(`/observability/alerts/${id}/ack`, {}); await loadAlerts() }
async function saveSettings() { await client.put('/observability/settings', settings.value); message.value = text('设置已保存', 'Settings saved') }
async function rotateToken() { scrapeToken.value = (await client.post('/observability/token', {})).data.token; metricsConfigured.value = true }
async function revokeToken() { await client.delete('/observability/token'); scrapeToken.value = ''; metricsConfigured.value = false }
async function copyToken() { await navigator.clipboard.writeText(scrapeToken.value); message.value = text('已复制', 'Copied') }
onMounted(() => run(async () => { const { data } = await client.get('/observability/settings'); settings.value = { retention_days: data.retention_days, offline_seconds: data.offline_seconds, drift_seconds: data.drift_seconds, node_latency_ms: data.node_latency_ms }; metricsConfigured.value = data.metrics_token_configured; await load() }))
const timer = setInterval(() => { if (!document.hidden && !busy.value) void run(load) }, 30000)
onBeforeUnmount(() => { clearInterval(timer); scrapeToken.value = '' })
</script>
<style scoped>
.operations{max-width:1200px}.card{padding:1.25rem;margin:1rem 0}.event,.actions{display:flex;gap:1rem;align-items:center}.event{justify-content:space-between;padding:.8rem 0;border-bottom:1px solid var(--paper-border)}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.65rem;border-bottom:1px solid var(--paper-border);vertical-align:top}.last-error{max-width:24rem;overflow-wrap:anywhere}label{display:block;margin:.8rem 0}input[type=number]{display:block;max-width:18rem;margin-top:.3rem}.settings{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 1rem}.settings p{grid-column:1/-1}.settings button{justify-self:start}.token{display:block;overflow-wrap:anywhere;background:var(--paper-muted);padding:1rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}details{margin-top:1rem}.notice{padding:1rem;background:var(--paper-muted)}.error{color:#b63c3c}@media(max-width:700px){.settings{grid-template-columns:1fr}.actions{flex-wrap:wrap}}
</style>
