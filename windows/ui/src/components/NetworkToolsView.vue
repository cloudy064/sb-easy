<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, ref, watch } from 'vue'
import type { NativeBridge } from '../lib/bridge'
import type { ConfigInspection, RuntimeSnapshot } from '../lib/protocol'
import { bytes, ruleAction, shortVersion } from '../lib/dashboard'
import LogsView from './LogsView.vue'
import AppIcon from './AppIcon.vue'
const props = defineProps<{ bridge: NativeBridge; initialTab?: 'connections' | 'rules'; standalone?: boolean }>()
const tab = ref<'connections' | 'rules' | 'logs'>(props.initialTab ?? 'connections'), source = ref<'active' | 'candidate'>('active')
const runtime = ref<RuntimeSnapshot | null>(null), config = ref<ConfigInspection | null>(null)
const query = ref(''), protocol = ref('all'), busy = ref(false), error = ref('')
let disposed = false, timer: ReturnType<typeof setTimeout> | undefined
const catalog = computed(() => config.value?.[source.value])
const connections = computed(() => (runtime.value?.connections ?? []).filter(c => (protocol.value === 'all' || c.network.toLowerCase() === protocol.value) && `${c.host} ${c.destination} ${c.process} ${c.rule} ${c.chains.join(' ')}`.toLowerCase().includes(query.value.toLowerCase())))
const rules = computed(() => (catalog.value?.rules ?? []).filter(r => `${r.title} ${r.match} ${r.outbound} ${r.action}`.toLowerCase().includes(query.value.toLowerCase())))
async function refresh() {
  if(busy.value || tab.value === 'logs')return
  busy.value = true
  try {
    if(tab.value === 'connections') runtime.value = await props.bridge.request('runtime.snapshot')
    else config.value = await props.bridge.request('config.inspect')
    error.value = ''
  } catch(e) { error.value = e instanceof Error ? e.message : '无法读取排查信息' }
  finally { busy.value = false }
}
async function poll(){if(document.visibilityState === 'visible')await refresh();if(!disposed)timer=setTimeout(poll,3000)}
watch(tab,()=>{query.value='';error.value='';void refresh()})
onMounted(poll);onBeforeUnmount(()=>{disposed=true;clearTimeout(timer)})
</script>
<template>
  <section v-if="!standalone" class="panel tools-intro"><h2>网络排查</h2><p>查看当前连接、有效规则和脱敏日志。服务出口仍在“连接”页面修改。</p><div class="segments" aria-label="排查工具"><button v-for="item in [{id:'connections',name:'活动连接'},{id:'rules',name:'规则详情'},{id:'logs',name:'运行日志'}] as const" :key="item.id" :class="{active:tab===item.id}" @click="tab=item.id">{{ item.name }}</button></div></section>
  <LogsView v-if="tab==='logs'" :bridge="bridge" />
  <template v-else>
    <div class="content-toolbar"><label class="search-box"><AppIcon name="search"/><input v-model="query" :aria-label="tab==='rules'?'搜索规则':'搜索连接'" :placeholder="tab==='rules'?'搜索域名、规则或出口':'搜索应用、域名或出口'"/></label><button class="secondary-button" :disabled="busy" @click="refresh">{{ busy?'读取中…':'刷新' }}</button></div>
    <p v-if="error" class="notice error" role="alert">{{ error }}</p>
    <template v-if="tab==='connections'">
      <div class="content-toolbar"><div class="segments"><button v-for="p in ['all','tcp','udp']" :key="p" :class="{active:protocol===p}" @click="protocol=p">{{ p==='all'?'全部':p.toUpperCase() }}</button></div><span class="input-hint">{{ runtime?.running ? `${runtime.connection_count} 个活动连接`:'连接尚未启动' }}</span></div>
      <div class="panel table-panel"><table v-if="connections.length"><thead><tr><th>目标 / 应用</th><th>出口 / 规则</th><th>流量</th></tr></thead><tbody><tr v-for="c in connections" :key="c.id"><td><strong>{{ c.host || c.destination }}:{{ c.port }}</strong><span class="table-sub">{{ c.process || c.type }} · {{ c.network.toUpperCase() }}</span></td><td>{{ c.chains.join(' → ') || '未提供出口' }}<span class="table-sub">{{ c.rule || '未提供规则' }}</span></td><td><span class="table-sub">↑ {{ bytes(c.upload) }}</span><span class="table-sub">↓ {{ bytes(c.download) }}</span></td></tr></tbody></table><div v-else class="empty-state"><h2>{{ error?'连接数据暂不可用':'暂无匹配的活动连接' }}</h2><p>这里只显示当前内核的连接，不保留已结束的访问记录。</p></div></div>
      <p class="collection-note">每 3 秒刷新 · 最多展示 128 条连接 · 历史流量需安装“流量统计”扩展。</p>
    </template>
    <template v-else>
      <div class="content-toolbar"><div class="segments"><button :class="{active:source==='active'}" @click="source='active'">当前运行</button><button :class="{active:source==='candidate'}" @click="source='candidate'">已下载配置</button></div><span class="input-hint">{{ shortVersion(catalog?.etag) }}</span></div>
      <div class="service-routing-grid"><article v-for="rule in rules" :key="rule.index" class="panel service-routing-card"><div class="section-heading"><h2>{{ rule.title || '分流规则' }}</h2><span class="input-hint">优先级 {{ rule.index }}</span></div><strong>{{ rule.outbound==='direct'?'直接连接':rule.outbound || ruleAction(rule.action) }}</strong><p>{{ rule.match }}</p></article></div>
      <div v-if="!rules.length" class="panel empty-state"><h2>{{ catalog?'没有匹配的规则':'尚无对应配置' }}</h2><p>可切换配置来源，或先同步配置再查看。</p></div><p class="collection-note">规则按顺序匹配，首次命中生效。长条件展示前 3 项；管理连接另有直连保护。</p>
    </template>
  </template>
</template>
<style scoped>.tools-intro{padding:22px;margin-bottom:20px}.tools-intro p{color:var(--secondary);font-size:13px;line-height:1.8;margin:12px 0 20px}.tools-intro .segments{display:inline-flex}.service-routing-card p{overflow-wrap:anywhere}.table-panel td{overflow-wrap:anywhere}</style>
