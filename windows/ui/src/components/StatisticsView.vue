<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import type { NativeBridge } from '../lib/bridge'
import type { TrafficSnapshot } from '../lib/protocol'
import { bytes } from '../lib/dashboard'
import { groupTraffic } from '../lib/traffic'
const props = defineProps<{ bridge: NativeBridge }>()
const snapshot = ref<TrafficSnapshot | null>(null)
const mode = ref<'app' | 'domain'>('app')
const scope = ref(''), host = ref(''), query = ref(''), sort = ref('total')
const error = ref(''), busy = ref(false), confirmClear = ref(false), paused = ref(false)
let disposed = false, timer: ReturnType<typeof setTimeout> | undefined
const roots = computed(() => groupTraffic(snapshot.value?.rows ?? [], mode.value))
const selected = computed(() => roots.value.find(row => row.key === scope.value))
const hosts = computed(() => groupTraffic(selected.value?.rows ?? [], 'host'))
const selectedHost = computed(() => hosts.value.find(row => row.key === host.value))
const groups = computed(() => {
  const rows = host.value ? groupTraffic(selectedHost.value?.rows ?? [], 'outbound') : scope.value ? hosts.value : roots.value
  return rows.filter(row => row.key.toLowerCase().includes(query.value.toLowerCase())).sort((a, b) =>
    sort.value === 'recent' ? b.lastSeen - a.lastSeen : sort.value === 'upload' ? b.upload - a.upload :
      sort.value === 'download' ? b.download - a.download : b.upload + b.download - a.upload - a.download)
})
const totals = computed(() => (snapshot.value?.rows ?? []).reduce((sum, row) => ({ up: sum.up + row.upload, down: sum.down + row.download }), { up: 0, down: 0 }))
const maximum = computed(() => Math.max(1, ...groups.value.map(row => row.upload + row.download)))
watch(mode, () => { scope.value = ''; host.value = ''; query.value = '' })
function drill(key: string) { if (!scope.value) scope.value = key; else if (!host.value) host.value = key; query.value = '' }
function time(value: number) { return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '尚未采集' }
async function refresh(clear = false) {
  if (busy.value) return
  busy.value = true
  try {
    const next = await props.bridge.request(clear ? 'traffic.clear' : 'traffic.snapshot')
    if (disposed) return
    snapshot.value = next; error.value = ''
    if (clear) { confirmClear.value = false; scope.value = ''; host.value = '' }
  } catch (e) { if (!disposed) error.value = e instanceof Error ? e.message : '统计读取失败' }
  finally { busy.value = false }
}
async function poll() {
  if (!paused.value && document.visibilityState === 'visible') await refresh()
  if (!disposed) timer = setTimeout(() => void poll(), 3000)
}
onMounted(() => void poll())
onBeforeUnmount(() => { disposed = true; clearTimeout(timer) })
</script>
<template>
  <div class="content-toolbar"><div class="segments"><button :class="{ active: mode === 'app' }" @click="mode = 'app'">按应用</button><button :class="{ active: mode === 'domain' }" @click="mode = 'domain'">按域名</button></div><div class="stat-actions"><button class="secondary-button" @click="paused = !paused">{{ paused ? '继续刷新' : '暂停刷新' }}</button><button class="secondary-button" :disabled="busy" @click="refresh()">刷新</button><button class="secondary-button" @click="confirmClear = true">清空统计</button></div></div>
  <section v-if="confirmClear" class="panel stat-confirm"><strong>清空累计流量和访问记录？</strong><p>不会断开连接。此操作不可撤销，当前连接之后产生的流量会继续统计。</p><button class="primary-button" :disabled="busy" @click="refresh(true)">确认清空</button><button class="secondary-button" @click="confirmClear = false">取消</button></section>
  <p v-if="error" class="inline-error" role="alert">{{ error }}</p>
  <div class="stat-summary"><section class="panel"><span>内核累计上传</span><strong>{{ bytes(snapshot?.upload ?? 0) }}</strong></section><section class="panel"><span>内核累计下载</span><strong>{{ bytes(snapshot?.download ?? 0) }}</strong></section><section class="panel"><span>已归属应用 / 域名</span><strong>{{ bytes(totals.up + totals.down) }}</strong></section><section class="panel"><span>未归属流量</span><strong>{{ bytes(Math.max(0, (snapshot?.upload ?? 0) + (snapshot?.download ?? 0) - totals.up - totals.down)) }}</strong></section></div>
  <nav class="stat-breadcrumb" aria-label="统计层级"><button class="text-button" @click="scope = ''; host = ''; query = ''">{{ mode === 'app' ? '全部应用' : '全部域名' }}</button><template v-if="scope"><span> / </span><button class="text-button" @click="host = ''; query = ''">{{ scope }}</button></template><template v-if="host"><span> / </span><strong>{{ host }}</strong></template></nav>
  <div class="content-toolbar"><input v-model="query" class="stat-search" :placeholder="host ? '搜索出站' : scope ? '搜索 host' : '搜索应用或域名'" aria-label="搜索统计"/><select v-model="sort" aria-label="统计排序"><option value="total">总流量优先</option><option value="download">下载优先</option><option value="upload">上传优先</option><option value="recent">最近访问</option></select></div>
  <section class="panel stat-table"><div class="stat-table-header"><span>{{ host ? '出站' : scope ? 'Host' : mode === 'app' ? '应用' : '域名' }}</span><span>上传</span><span>下载</span><span>最近访问</span></div><button v-for="row in groups" :key="row.key" class="stat-table-row" :disabled="!!host" @click="drill(row.key)"><span class="stat-name"><strong>{{ row.key }}</strong><small>{{ host ? [...new Set(row.rows.map(item => item.rule))].filter(Boolean).join(' · ') || '默认路由' : `${row.hosts} 个 host · 点击查看${scope ? '出站' : '明细'}` }}</small><i :style="{ width: `${(row.upload + row.download) / maximum * 100}%` }"></i></span><span>{{ bytes(row.upload) }}</span><span>{{ bytes(row.download) }}</span><time>{{ time(row.lastSeen) }}</time></button><div v-if="!groups.length" class="empty-state"><h2>{{ query ? '没有匹配结果' : '暂无统计记录' }}</h2><p>连接后访问网络，后台服务会自动采集。</p></div></section>
  <p class="collection-note">统计起点：{{ time(snapshot?.cleared_at ?? 0) }} · 最近采集：{{ time(snapshot?.sampled_at ?? 0) }}。服务每 2 秒采样，关闭窗口后继续采集；每 30 秒保存。短连接及结束前未采到的流量计入未归属部分。应用以进程文件名归类。</p>
  <p v-if="snapshot?.limited" class="inline-error">已达到明细容量（512 组或本次内核运行 20,000 条连接）。总流量继续累计，新增明细可能缺失；清空统计可释放明细容量。</p>
  <p v-if="snapshot && !snapshot.storage_ok" class="inline-error">统计存储不可用，本次数据仅保留在服务内存中。</p>
</template>
<style>
.stat-actions{display:flex;gap:8px;flex-wrap:wrap}.stat-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:20px 0}.stat-summary section{padding:20px}.stat-summary span{display:block;font-size:12px;color:var(--muted)}.stat-summary strong{display:block;font-size:24px;margin-top:10px}.stat-breadcrumb{display:flex;flex-direction:row;justify-content:flex-start;align-items:center;flex-wrap:wrap;gap:8px;margin:14px 0;overflow-wrap:anywhere}.stat-search{width:min(420px,65%);padding:10px;font-size:13px;border:1px solid var(--border);border-radius:10px;background:var(--surface);color:inherit}.panel.stat-table{overflow:hidden;padding:0}.stat-table-header,.stat-table-row{display:grid;grid-template-columns:minmax(160px,1fr) 90px 90px 155px;align-items:center;gap:16px;padding:16px 22px;text-align:left}.stat-table-header{font-size:12px;color:var(--muted);border-bottom:1px solid var(--border)}.stat-table-row{width:100%;border:0;border-bottom:1px solid var(--border);background:transparent;color:inherit;cursor:pointer;font:inherit;font-size:13px}.stat-table-row:hover{background:var(--accent-bg)}.stat-table-row:disabled{opacity:1;cursor:default}.stat-name{min-width:0}.stat-name strong,.stat-name small{display:block;overflow-wrap:anywhere}.stat-name small{margin:7px 0;color:var(--muted);font-size:11px}.stat-name i{display:block;height:3px;background:#279a82;border-radius:4px}.stat-table-row time{font-size:11px;color:var(--muted)}.stat-confirm{padding:20px;margin-bottom:20px}.stat-confirm button{margin-right:10px}@media(max-width:800px){.stat-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.stat-table-header,.stat-table-row{grid-template-columns:minmax(120px,1fr) 75px 75px}.stat-table-row time,.stat-table-header>span:last-child{display:none}}
.stat-breadcrumb button{padding:6px 0;width:auto}.content-toolbar select{font:inherit;font-size:12px;padding:9px 12px;border:1px solid var(--border);border-radius:8px;color:var(--ink);background:var(--surface)}
</style>
