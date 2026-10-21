<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import type { NativeBridge } from '../lib/bridge'
import type { IpCheckCatalog, IpCheckState, IpCheckResult, IpCheckMeasurement } from '../lib/ipcheck'
import { dataSourceStatus, fieldSourceLabel, infoLabel, listCheckLabel, measurementLabel, probeErrorLabel, sourceDate, sourceForCheck, sourceForField } from '../lib/ipcheck'

const props = defineProps<{ bridge: NativeBridge }>()
const catalog = ref<IpCheckCatalog>({ nodes: [], interfaces: [], default_interface: '' })
const state = ref<IpCheckState>({ phase: 'idle', results: [], error: '', summary: { status: 'failed', node_count: 0, processed_count: 0, measured_count: 0, info_count: 0, complete_count: 0 } })
const selected = ref<string[]>([])
const ipv6 = ref(true)
const search = ref('')
const source = ref('')
const busy = ref(false)
const loading = ref(true)
const error = ref('')
let disposed = false
let generation = 0
let polling = false
let timer: ReturnType<typeof setTimeout> | undefined

const running = computed(() => state.value.phase === 'running')
const locked = computed(() => busy.value || loading.value || running.value)
const sources = computed(() => [...new Set(catalog.value.nodes.map(node => node.source).filter((value): value is string => Boolean(value)))])
const visibleNodes = computed(() => {
  const query = search.value.trim().toLocaleLowerCase()
  return catalog.value.nodes.filter(node => (!source.value || node.source === source.value) && (!query || `${node.tag} ${node.type} ${node.source ?? ''}`.toLocaleLowerCase().includes(query)))
})
const percent = computed(() => state.value.summary.node_count ? Math.round(state.value.summary.processed_count / state.value.summary.node_count * 100) : 0)
const phaseLabel = computed(() => ({ idle: '准备检测', running: state.value.cancel_requested ? '正在取消' : '正在检测', complete: '检测完成', partial: '部分结果可用', failed: '检测未完成', cancelled: '已取消，结果已保留' })[state.value.phase])
const canStart = computed(() => !locked.value && selected.value.length > 0)

function nodeLabel(tag: string): string { return tag.replace(/^local-[a-f0-9-]{36}\//, '') }
function toggle(tag: string): void {
  if (locked.value) return
  selected.value = selected.value.includes(tag) ? selected.value.filter(item => item !== tag) : [...selected.value, tag].slice(0, 100)
}
function selectVisible(): void {
  if (!locked.value) selected.value = [...new Set([...selected.value, ...visibleNodes.value.map(node => node.tag)])].slice(0, 100)
}
function clearTimer(): void { if (timer) clearTimeout(timer); timer = undefined }
function schedule(): void {
  clearTimer()
  if (!disposed && !document.hidden && !busy.value) timer = setTimeout(poll, running.value ? 1500 : 10000)
}
async function poll(): Promise<void> {
  if (disposed || busy.value || polling || document.hidden) return
  const current = generation
  polling = true
  try {
    const latest = await props.bridge.request('ipcheck.snapshot')
    if (!disposed && current === generation) { state.value = latest; error.value = '' }
  } catch (cause) {
    if (!disposed && current === generation) error.value = cause instanceof Error ? cause.message : '暂时无法读取检测进度'
  } finally { polling = false; schedule() }
}
async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const [available, latest] = await Promise.all([props.bridge.request('ipcheck.catalog'), props.bridge.request('ipcheck.snapshot')])
    if (disposed) return
    catalog.value = available
    state.value = latest
    selected.value = selected.value.filter(tag => available.nodes.some(node => node.tag === tag))
  } catch (cause) {
    if (!disposed) error.value = cause instanceof Error ? cause.message : '无法读取中心节点'
  } finally { loading.value = false; schedule() }
}
async function start(): Promise<void> {
  if (!canStart.value) return
  busy.value = true
  error.value = ''
  generation++
  clearTimer()
  try {
    const latest = await props.bridge.request('ipcheck.start', { tags: [...selected.value], ipv6: ipv6.value }, { timeoutMs: 15_000 })
    if (!disposed) state.value = latest
  } catch (cause) {
    if (!disposed) error.value = cause instanceof Error ? cause.message : '未能开始检测'
    // A lost reply is not proof that the worker did not start; never replay start.
    try { const latest = await props.bridge.request('ipcheck.snapshot'); if (!disposed) state.value = latest } catch { /* Keep the original failure and previous results. */ }
  } finally { busy.value = false; schedule() }
}
async function cancel(): Promise<void> {
  if (busy.value || !running.value || state.value.cancel_requested) return
  busy.value = true
  generation++
  clearTimer()
  try {
    const latest = await props.bridge.request('ipcheck.cancel', {}, { timeoutMs: 15_000 })
    if (!disposed) { state.value = latest; error.value = '' }
  } catch (cause) {
    if (!disposed) error.value = cause instanceof Error ? cause.message : '取消请求未完成，请重试'
  } finally { busy.value = false; schedule() }
}
function visibilityChanged(): void {
  if (document.hidden) clearTimer()
  else void poll()
}
function families(result: IpCheckResult): { family: number; measurement?: IpCheckMeasurement; requested: boolean }[] {
  return [{ family: 4, measurement: result.ipv4, requested: true }, { family: 6, measurement: result.ipv6, requested: result.ipv6_requested }]
}
function location(measurement?: IpCheckMeasurement): string {
  const fields = measurement?.ip_info?.fields
  return [...new Set([fields?.country || fields?.country_code, fields?.region, fields?.city].filter(Boolean))].join(' · ') || '地区未知'
}
function checkedAt(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
onMounted(() => { void load(); document.addEventListener('visibilitychange', visibilityChanged) })
onUnmounted(() => { disposed = true; generation++; clearTimer(); document.removeEventListener('visibilitychange', visibilityChanged) })
</script>

<template>
  <section class="ipcheck-panel" aria-labelledby="ipcheck-title">
    <header class="ipcheck-header">
      <div><span class="eyebrow">IP CHECK</span><h2 id="ipcheck-title">一次看清各个节点的出口</h2><p>中心服务统一检测，同一配置的设备共享结果。</p></div>
      <span class="local-badge">中心检测</span>
    </header>
    <p class="source-note">检测从中心服务器发起，经指定节点获取出口 IP；地区、ASN 和公开名单在中心查询。资料缺失时显示“未知”；过期数据会标注日期与状态。</p>
    <p v-if="error || state.error" class="error-notice" role="alert">{{ error || probeErrorLabel(state.error) }}</p>

    <div class="setup-grid">
      <section class="node-picker" aria-labelledby="ipcheck-nodes">
        <div class="section-title"><h3 id="ipcheck-nodes">选择节点</h3><span>{{ selected.length }} / 100</span></div>
        <div class="filters"><input v-model="search" type="search" placeholder="搜索节点、协议或订阅" aria-label="搜索节点"/><select v-if="sources.length" v-model="source" aria-label="筛选订阅"><option value="">全部订阅</option><option v-for="item in sources" :key="item" :value="item">{{ item }}</option></select></div>
        <div class="selection-actions"><button :disabled="locked || !visibleNodes.length || selected.length >= 100" @click="selectVisible">选择当前列表</button><button :disabled="locked || !selected.length" @click="selected = []">清空选择</button><button class="refresh" :disabled="locked" @click="load">刷新节点</button></div>
        <div class="node-list" :aria-busy="loading">
          <p v-if="loading" class="empty-small">正在读取中心节点…</p>
          <p v-else-if="!visibleNodes.length" class="empty-small">{{ catalog.nodes.length ? '没有匹配的节点' : '暂无可检测的节点，请先同步或添加订阅。' }}</p>
          <label v-for="node in visibleNodes" v-else :key="node.tag" class="node-option" :class="{ chosen: selected.includes(node.tag) }">
            <input type="checkbox" :checked="selected.includes(node.tag)" :disabled="locked || (!selected.includes(node.tag) && selected.length >= 100)" @change="toggle(node.tag)"/>
            <span><strong>{{ nodeLabel(node.tag) }}</strong><small>{{ node.source || '订阅来源未提供' }}</small></span><span class="node-type">{{ node.type }}</span>
          </label>
        </div>
        <p class="hint">每次最多 100 个节点，按顺序检测；相同出口的资料会复用。</p>
      </section>

      <section class="check-settings" aria-labelledby="ipcheck-options">
        <h3 id="ipcheck-options">检测选项</h3>
        <p class="hint">执行位置：中心服务器。无需选择本机网卡，也不会切换任何客户端的代理。</p>
        <p class="hint">仅检测中心配置中的节点。本机独有订阅不会自动上传；结果代表中心测得的出口，显示完整检测时间。</p>
        <label class="ipv6-option"><input v-model="ipv6" type="checkbox" :disabled="locked"/><span><strong>同时检测 IPv6 出口</strong><small>IPv6 未成功不代表节点不支持，也不能据此判断有无泄漏。</small></span></label>
        <button v-if="!running" class="primary start-button" :disabled="!canStart" @click="start">{{ busy ? '正在启动…' : `检测所选 ${selected.length} 个节点` }}<span aria-hidden="true">→</span></button>
        <button v-else class="start-button" :disabled="busy || state.cancel_requested" @click="cancel">{{ state.cancel_requested ? '正在取消…' : '取消检测' }}</button>
        <p class="hint">只检测当前选中的节点。开始新一轮时替换同一配置的上轮结果；离开页面后中心继续检测。</p>
      </section>
    </div>

    <section class="results" aria-labelledby="ipcheck-results">
      <div class="results-heading"><div><h3 id="ipcheck-results">检测结果</h3><p role="status" aria-live="polite">{{ phaseLabel }}<template v-if="state.phase !== 'idle'"> · {{ state.summary.processed_count }} / {{ state.summary.node_count }} 个节点</template></p></div><div v-if="state.summary.processed_count" class="result-counts"><span><strong>{{ state.summary.measured_count }}</strong> IPv4 出口</span><span><strong>{{ state.summary.info_count }}</strong> 份 IPv4 资料</span></div></div>
      <progress v-if="running" :value="percent" max="100" aria-label="节点检测进度"/>
      <div v-if="!state.results.length" class="results-empty"><span aria-hidden="true">◎</span><h4>{{ running ? '正在等待首个节点的结果' : state.phase === 'idle' ? '勾选节点，开始比较出口' : phaseLabel }}</h4><p>{{ running ? '每个节点需要建立独立连接，结果将逐个显示。' : '这里显示实际检测结果，不使用节点名称推测地区。' }}</p></div>
      <article v-for="result in state.results" :key="result.node" class="result-card">
        <header class="result-title"><h4>{{ nodeLabel(result.node) }}</h4><time :datetime="result.checked_at">{{ checkedAt(result.checked_at) }}</time></header>
        <p v-if="result.status === 'unknown'" class="inline-warning">{{ probeErrorLabel(result.reason) }}</p>
        <div class="families">
          <section v-for="entry in families(result)" :key="entry.family" class="family-result" :class="{ unavailable: entry.measurement?.status !== 'ok' }">
            <div class="address-row"><span class="family-badge">IPv{{ entry.family }}</span><code>{{ measurementLabel(entry.measurement, entry.family, entry.requested) }}</code></div>
            <template v-if="entry.measurement?.status === 'ok'">
              <div class="metadata-label" :class="{ warning: entry.measurement.ip_info?.status !== 'ok' || entry.measurement.ip_info?.partial }">{{ infoLabel(entry.measurement.ip_info) }}<span v-if="entry.measurement.ip_info_cached"> · 同出口复用</span></div>
              <template v-if="entry.measurement.ip_info?.provider === 'sb-easy-offline'">
                <dl class="network-details">
                  <div><dt>国家 / 地区</dt><dd>{{ location(entry.measurement) }}<small v-if="sourceForField(entry.measurement.ip_info, 'country')">{{ fieldSourceLabel(sourceForField(entry.measurement.ip_info, 'country')) }}</small></dd></div>
                  <div><dt>ASN</dt><dd>{{ entry.measurement.ip_info.fields?.asn || '未知' }}<small v-if="sourceForField(entry.measurement.ip_info, 'asn')">{{ fieldSourceLabel(sourceForField(entry.measurement.ip_info, 'asn')) }}</small></dd></div>
                  <div><dt>网络组织</dt><dd>{{ entry.measurement.ip_info.fields?.organization || '未知' }}<small v-if="sourceForField(entry.measurement.ip_info, 'organization')">{{ fieldSourceLabel(sourceForField(entry.measurement.ip_info, 'organization')) }}</small></dd></div>
                </dl>
                <div class="list-checks">
                  <div v-for="check in entry.measurement.ip_info.checks" :key="check.id" class="list-check" :class="check.status">
                    <div class="check-line"><span>{{ { datacenter: '机房网段', vpn: 'VPN 网段', tor: 'Tor 出口' }[check.id] }}</span><strong>{{ listCheckLabel(check) }}</strong></div>
                    <small>{{ sourceForCheck(entry.measurement.ip_info, check)?.name || check.source }} · {{ sourceDate(check.updated_at || sourceForCheck(entry.measurement.ip_info, check)?.updated_at) }}</small>
                    <code v-if="check.status === 'listed' && check.network">{{ check.network }}</code>
                  </div>
                </div>
                <details class="data-sources">
                  <summary>数据来源与版本</summary>
                  <p v-if="entry.measurement.ip_info.database" class="database-version">数据包 {{ entry.measurement.ip_info.database.version }} · 生成于 {{ sourceDate(entry.measurement.ip_info.database.generated_at) }}</p>
                  <ul><li v-for="item in entry.measurement.ip_info.sources" :key="item.id"><div class="source-heading"><strong>{{ item.name }}</strong><span :class="{ 'source-warning': item.status !== 'ready' }">{{ dataSourceStatus(item) }}</span></div><p>{{ item.license }} · {{ item.families.length ? item.families.map(family => `IPv${family}`).join(' / ') : '地址类型未提供' }}<br/>数据日期 {{ sourceDate(item.updated_at) }} · 获取日期 {{ sourceDate(item.retrieved_at) }}</p><span class="source-url">{{ item.url }}</span></li></ul>
                </details>
              </template>
              <template v-else-if="entry.measurement.ip_info?.status === 'ok'">
                <p class="location">{{ location(entry.measurement) }}</p><p class="network">{{ entry.measurement.ip_info.fields?.asn || 'ASN 未知' }} · {{ entry.measurement.ip_info.fields?.organization || '机构未知' }}</p><p class="hint">这是之前数据源的记录，重新检测后将使用本地公开数据。</p>
              </template>
              <p v-else class="hint">出口 IP 已测得。资料查询失败不表示节点不可用，也不表示这个 IP 安全或有风险。</p>
            </template>
            <p v-else-if="entry.requested && entry.measurement?.reason" class="hint">{{ probeErrorLabel(entry.measurement.reason) }}</p>
          </section>
        </div>
      </article>
      <p v-if="state.results.length" class="footnote">“未命中此名单”只表示这份名单没有记录，不等于住宅 IP 或没有风险。地区是数据库记录；本次检测不提供滥用历史、风险评分或 Claude、ChatGPT 等服务的可用性结论。</p>
    </section>
  </section>
</template>

<style scoped>
.ipcheck-panel{--muted:var(--secondary,#6f7975);color:var(--ink,#1e2c26);max-width:1100px;border:1px solid var(--border,#e3e7e3);border-radius:20px;padding:28px;background:var(--surface,#fff)}
.ipcheck-header,.section-title,.results-heading,.result-title,.address-row{display:flex;align-items:center;justify-content:space-between;gap:16px}.eyebrow{color:var(--accent,#317460);font-size:10px;letter-spacing:2px;font-weight:600}h2{font-size:25px;letter-spacing:-.5px;margin:12px 0 8px}h3{font-size:15px;margin:0}h4{font-size:14px;margin:0;overflow-wrap:anywhere}p{font-size:12px;line-height:1.8;color:var(--muted)}.ipcheck-header p{margin:0;font-size:13px}.local-badge{font-size:11px;white-space:nowrap;border:1px solid var(--border,#dbe1dd);background:var(--accent-bg,#e9f4ee);padding:7px 11px;border-radius:20px;color:var(--accent,#317460)}.source-note{margin:22px 0;padding:13px 16px;border-radius:10px;background:#63836d0b;border:1px solid #63836d22}.setup-grid{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(230px,1fr);gap:24px}.node-picker,.check-settings{min-width:0;border:1px solid var(--border,#e3e7e3);border-radius:14px;padding:18px}.section-title>span{color:var(--muted);font-size:12px}.filters{display:flex;gap:8px;margin:16px 0 4px}.filters input{min-width:0;flex:1}.filters select{max-width:42%}input[type=search],select{font:inherit;font-size:12px;color:inherit;background:var(--surface,#fff);border:1px solid var(--border,#dbe1dd);border-radius:8px;padding:10px;box-sizing:border-box;min-height:38px}select{padding-right:24px}button{font:inherit;font-size:12px;cursor:pointer;color:inherit;background:transparent;border:1px solid var(--border,#dbe1dd);border-radius:8px;padding:9px 12px}button:disabled,input:disabled,select:disabled{opacity:.45;cursor:default}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--accent,#317460);outline-offset:3px}.selection-actions{display:flex;align-items:center;gap:12px;margin:7px 0}.selection-actions button{border:0;padding:6px 0;color:var(--muted);font-size:11px}.selection-actions .refresh{margin-left:auto}.node-list{max-height:260px;min-height:130px;overflow:auto;border-top:1px solid var(--border,#e3e7e3)}.node-option{display:flex;align-items:center;gap:10px;padding:12px 8px;border-bottom:1px solid #8881;cursor:pointer;border-radius:5px}.node-option.chosen{background:var(--accent-bg,#e9f4ee)}.node-option>span:nth-child(2){min-width:0;flex:1}.node-option strong,.node-option small{display:block;overflow-wrap:anywhere}.node-option strong{font-size:12px;font-weight:500}.node-option small{color:var(--muted);font-size:10px;margin-top:4px}.node-type{font-size:10px;color:var(--muted)}input[type=checkbox]{accent-color:var(--accent,#317460);width:15px;height:15px;flex-shrink:0;margin:0}.field-label{display:block;font-size:12px;margin:22px 0 8px}.check-settings select{width:100%}.hint{font-size:11px;line-height:1.8;margin:10px 0 0}.ipv6-option{display:flex;align-items:flex-start;gap:10px;margin:24px 0}.ipv6-option input{margin-top:2px}.ipv6-option strong,.ipv6-option small{display:block;font-size:12px;font-weight:500}.ipv6-option small{color:var(--muted);font-size:11px;line-height:1.8;margin-top:6px;font-weight:400}.start-button{display:flex;justify-content:space-between;width:100%;padding:12px 16px}.primary{background:#317460;color:#fff;border-color:#317460}.results{margin-top:28px;border-top:1px solid var(--border,#e3e7e3);padding-top:24px}.results-heading p{margin:6px 0 0}.result-counts{display:flex;gap:20px;font-size:10px;color:var(--muted)}.result-counts strong{font-size:18px;color:var(--ink,#1e2c26);display:block;margin-bottom:5px}.results progress{width:100%;height:4px;accent-color:var(--accent,#317460);margin:16px 0}.results-empty{text-align:center;padding:40px 12px;color:var(--muted)}.results-empty>span{font-size:32px;color:var(--accent,#317460);display:block;margin-bottom:12px}.results-empty h4{font-weight:500}.result-card{border:1px solid var(--border,#e3e7e3);border-radius:12px;margin-top:16px;overflow:hidden}.result-title{padding:14px 18px;background:#63836d07}.result-title time{white-space:nowrap;font-size:10px;color:var(--muted)}.families{display:grid;grid-template-columns:1fr 1fr}.family-result{padding:18px;min-width:0}.family-result+.family-result{border-left:1px solid var(--border,#e3e7e3)}.address-row{justify-content:flex-start;align-items:flex-start;gap:10px}.address-row code{font-family:Consolas,monospace;font-size:13px;line-height:1.7;overflow-wrap:anywhere}.family-badge{flex-shrink:0;font-size:9px;font-weight:600;background:var(--accent-bg,#e9f4ee);color:var(--accent,#317460);padding:4px 6px;border-radius:4px}.unavailable .address-row code{color:var(--muted);font-size:12px}.metadata-label{font-size:10px;color:var(--accent,#317460);margin-top:14px}.metadata-label.warning,.inline-warning{color:var(--secondary,#6f7975);font-weight:600}.location{font-size:13px;color:inherit;margin:8px 0 2px}.network{font-size:11px;margin:0;overflow-wrap:anywhere}.traits{display:flex;flex-wrap:wrap;gap:18px;margin:16px 0 0;font-size:10px}.traits div{display:flex;gap:6px}.traits dt{color:var(--muted)}.traits dd{margin:0}.footnote{font-size:11px;margin-top:18px}.error-notice{padding:12px 16px;background:var(--error-bg,#fff1ed);color:var(--error,#b64040);border-radius:9px}.inline-warning{font-size:11px}.result-card>.inline-warning{margin:12px 18px 0}.empty-small{text-align:center;padding:30px 8px;font-size:12px}
.network-details{margin:16px 0 18px;font-size:12px}.network-details>div{display:grid;grid-template-columns:75px minmax(0,1fr);gap:12px;margin:12px 0}.network-details dt{color:var(--muted);font-size:11px}.network-details dd{margin:0;overflow-wrap:anywhere;line-height:1.5}.network-details small,.list-check>small{display:block;font-size:10px;line-height:1.6;color:var(--muted);margin-top:4px}.list-checks{display:grid;gap:7px}.list-check{padding:10px 12px;border:1px solid var(--border,#e3e7e3);border-radius:8px;background:#63836d04}.check-line{display:flex;justify-content:space-between;align-items:baseline;gap:12px;font-size:11px}.check-line>strong{font-weight:500;text-align:right;color:var(--muted)}.listed .check-line>strong{color:var(--ink,#1e2c26);font-weight:600}.listed{border-color:#a4743538;background:#a4743507}.list-check>code{font-size:10px;display:block;margin-top:4px;overflow-wrap:anywhere}.data-sources{border-top:1px solid var(--border,#e3e7e3);margin-top:18px;padding-top:12px;font-size:10px;color:var(--muted)}.data-sources summary{cursor:pointer;font-size:11px;line-height:1.6}.data-sources summary:focus-visible{outline:2px solid var(--accent,#317460);outline-offset:3px}.data-sources ul{list-style:none;padding:0;margin:12px 0 0}.data-sources li+li{border-top:1px solid #8882;padding-top:10px;margin-top:10px}.source-heading{display:flex;align-items:baseline;justify-content:space-between;gap:10px}.source-heading strong{font-size:11px;color:var(--ink,#1e2c26);font-weight:500}.source-heading>span{white-space:nowrap}.source-heading .source-warning{color:var(--error,#a33e35)}.data-sources p{font-size:10px;margin:4px 0}.source-url{display:block;overflow-wrap:anywhere;line-height:1.6}.database-version{overflow-wrap:anywhere}
@media(max-width:850px){.setup-grid{grid-template-columns:1fr}.ipcheck-panel{padding:20px}.check-settings{display:block}.families{grid-template-columns:1fr}.family-result+.family-result{border-left:0;border-top:1px solid var(--border,#e3e7e3)}}
@media(max-width:560px){.ipcheck-panel{padding:15px}.ipcheck-header{align-items:flex-start}h2{font-size:21px}.local-badge{display:none}.filters{flex-direction:column}.filters select{max-width:100%}.result-counts{gap:10px}.results-heading{align-items:flex-start}.result-title{padding:12px}.family-result{padding:12px}}
</style>
