<template>
  <section class="card history-panel">
    <div class="flex-between controls"><h3>{{ text('历史流量', 'Traffic history') }}</h3><div class="controls">
      <label>{{ text('范围', 'Range') }} <select v-model.number="days"><option :value="1">24 {{ text('小时', 'hours') }}</option><option :value="7">7 {{ text('天', 'days') }}</option><option :value="30">30 {{ text('天', 'days') }}</option></select></label>
      <button class="btn-secondary btn-sm" :disabled="busy" @click="load">{{ text('刷新', 'Refresh') }}</button>
    </div></div>
    <p class="text-sm text-muted">{{ text('按中心接收时间采样，缺口表示未知。首次计数作为基线，重启可能丢失未上报流量；这些统计不作为计费依据。', 'Samples use server receipt time; gaps mean unknown. Initial counters form a baseline and restarts can lose unreported traffic. These statistics are not billing records.') }}</p>
    <p v-if="error" role="alert">{{ error }}</p>
    <div class="totals"><span>↑ {{ formatBytes(totals.up) }}</span><span>↓ {{ formatBytes(totals.down) }}</span><span>{{ text('计数重置', 'Counter resets') }}: {{ totals.resets }}</span></div>
    <p v-if="!rows.length && !busy" class="empty-state">{{ text('此范围内没有上报记录', 'No reports in this range') }}</p>
    <template v-else-if="rows.length">
      <div class="legend"><span class="up">↑ {{ text('上传', 'Upload') }}</span><span class="down">↓ {{ text('下载', 'Download') }}</span><span>{{ formatRate(maxRate) }}</span></div>
      <svg viewBox="0 0 960 210" role="img" :aria-label="text('上传与下载速率，空白表示无采样', 'Upload and download rates; blank regions have no samples')">
        <line x1="0" y1="190" x2="960" y2="190" stroke="currentColor" opacity=".25" />
        <g v-for="row in rows" :key="row.at"><rect class="bar up" :x="x(row.at)" :y="190 - height(row.up_average)" :width="barWidth" :height="height(row.up_average)"><title>{{ when(row.at) }} ↑ {{ formatRate(row.up_average) }}</title></rect>
          <rect class="bar down" :x="x(row.at) + barWidth" :y="190 - height(row.down_average)" :width="barWidth" :height="height(row.down_average)"><title>{{ when(row.at) }} ↓ {{ formatRate(row.down_average) }}</title></rect></g>
      </svg>
      <div class="flex-between text-xs text-muted"><span>{{ when(from) }}</span><span>{{ when(to) }}</span></div>
      <details><summary>{{ text('查看采样数据', 'View sample data') }}</summary><div class="table-wrap"><table><thead><tr><th>{{ text('时间', 'Time') }}</th><th>↑ / s</th><th>↓ / s</th><th>{{ text('连接峰值', 'Peak connections') }}</th><th>{{ text('样本数', 'Samples') }}</th></tr></thead><tbody><tr v-for="row in rows" :key="row.at"><td>{{ when(row.at) }}</td><td>{{ formatRate(row.up_average) }}</td><td>{{ formatRate(row.down_average) }}</td><td>{{ row.connections_max }}</td><td>{{ row.samples }}</td></tr></tbody></table></div></details>
    </template>
  </section>
</template>
<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import client from '../api/client'
import { formatBytes, formatRate } from '../api/realtime'
import { useI18n } from '../composables/i18n'
const props = defineProps<{ hostId: string }>(), { locale } = useI18n()
const text = (zh: string, en: string) => locale.value === 'zh' ? zh : en
interface Sample { at: number; samples: number; up_average: number; down_average: number; up_bytes: number; down_bytes: number; connections_max: number; counter_resets: number }
const days = ref(1), rows = ref<Sample[]>([]), from = ref(0), to = ref(0), step = ref(300), busy = ref(false), error = ref('')
let controller: AbortController | undefined, generation = 0
const totals = computed(() => rows.value.reduce((sum, row) => ({ up: sum.up + row.up_bytes, down: sum.down + row.down_bytes, resets: sum.resets + row.counter_resets }), { up: 0, down: 0, resets: 0 }))
const maxRate = computed(() => Math.max(1, ...rows.value.flatMap(row => [row.up_average, row.down_average])))
const height = (value: number) => Math.max(value > 0 ? 1 : 0, value / maxRate.value * 180)
const x = (at: number) => Math.max(0, (at - from.value) / Math.max(1, to.value - from.value) * 960)
const barWidth = computed(() => Math.max(.3, step.value / Math.max(1, to.value - from.value) * 960 / 2 - .2))
const when = (at: number) => new Date(at * 1000).toLocaleString()
async function load() {
  controller?.abort(); controller = new AbortController(); const current = ++generation
  if (!props.hostId) return
  busy.value = true; error.value = ''
  const end = Math.floor(Date.now() / 1000), interval = days.value === 1 ? 300 : days.value === 7 ? 3600 : 86400
  try {
    const { data } = await client.get(`/hosts/${encodeURIComponent(props.hostId)}/history`, { params: { from: Math.floor((end - days.value * 86400) / interval) * interval, to: end, step: interval }, signal: controller.signal })
    if (current !== generation) return
    rows.value = data.samples; from.value = data.from; to.value = data.to; step.value = data.step
  } catch (e: any) { if (current === generation && e.code !== 'ERR_CANCELED') error.value = e.response?.data?.error || e.message }
  finally { if (current === generation) busy.value = false }
}
watch([() => props.hostId, days], () => { rows.value = []; void load() }, { immediate: true })
const timer = setInterval(() => { if (!document.hidden) void load() }, 30000)
onBeforeUnmount(() => { ++generation; clearInterval(timer); controller?.abort() })
</script>
<style scoped>
.history-panel{padding:1.25rem}.controls,.totals,.legend{display:flex;gap:1rem;align-items:center;flex-wrap:wrap}.totals{margin:1rem 0;font-weight:600}.legend{font-size:.85rem}.up{color:#0f9f91;fill:#0f9f91}.down{color:#5c78d8;fill:#5c78d8}svg{display:block;width:100%;min-height:150px}.bar:hover{opacity:.6}details{margin-top:1rem}.table-wrap{overflow:auto;max-height:22rem}table{width:100%;border-collapse:collapse}td,th{padding:.6rem;text-align:left;border-bottom:1px solid var(--paper-border)}select{padding:.35rem}
</style>
