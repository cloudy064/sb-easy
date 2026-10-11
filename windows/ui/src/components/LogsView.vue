<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import type { NativeBridge } from '../lib/bridge'
const props = defineProps<{ bridge: NativeBridge }>()
const lines = ref<string[]>([]), query = ref(''), level = ref('all'), source = ref('all')
const paused = ref(false), busy = ref(false), error = ref('')
let disposed = false, timer: ReturnType<typeof setTimeout> | undefined
function severity(line: string) { return /\b(error|fatal|panic)\b/i.test(line) ? 'error' : /\bwarn(ing)?\b/i.test(line) ? 'warn' : /\bdebug\b/i.test(line) ? 'debug' : 'info' }
const filtered = computed(() => lines.value.filter(line => line.toLowerCase().includes(query.value.toLowerCase()) && (level.value === 'all' || severity(line) === level.value) && (source.value === 'all' || line.includes(` ${source.value} `))).slice().reverse())
async function refresh() {
  if (busy.value) return
  busy.value = true
  try { const result = await props.bridge.request('logs.snapshot'); if (!disposed) { lines.value = result.lines; error.value = '' } }
  catch (e) { if (!disposed) error.value = e instanceof Error ? e.message : '日志读取失败' }
  finally { busy.value = false }
}
async function poll() { if (!paused.value && document.visibilityState === 'visible') await refresh(); if (!disposed) timer = setTimeout(() => void poll(), 2000) }
onMounted(() => void poll()); onBeforeUnmount(() => { disposed = true; clearTimeout(timer) })
</script>
<template>
  <div class="content-toolbar"><input v-model="query" class="stat-search" placeholder="搜索域名、进程、节点或错误" aria-label="搜索日志"/><div class="stat-actions"><button class="secondary-button" @click="paused = !paused">{{ paused ? '继续刷新' : '暂停刷新' }}</button><button class="secondary-button" :disabled="busy" @click="refresh">刷新</button></div></div>
  <div class="content-toolbar"><div class="segments"><button v-for="item in [{ id:'all', label:'全部' },{ id:'core',label:'内核运行' },{ id:'service',label:'服务诊断' }]" :key="item.id" :class="{active:source === item.id}" @click="source = item.id">{{ item.label }}</button></div><select v-model="level" aria-label="日志级别"><option value="all">全部级别</option><option value="error">错误</option><option value="warn">警告</option><option value="info">信息</option><option value="debug">调试</option></select></div>
  <p v-if="error" class="inline-error" role="alert">{{ error }}</p>
  <section class="panel log-view" aria-label="运行日志"><div v-for="(line,index) in filtered" :key="`${index}:${line}`" class="log-line" :class="severity(line)"><span>{{ severity(line).toUpperCase() }}</span><code>{{ line.trim() }}</code></div><div v-if="!filtered.length" class="empty-state"><h2>暂无匹配日志</h2><p>启动连接后，内核 DNS、路由和连接记录会显示在这里。</p></div></section>
  <p class="collection-note">{{ paused ? '已暂停界面刷新' : '每 2 秒刷新' }} · 显示本次服务启动后的最近 200 行（新记录在前），已过滤凭据。完整历史请通过托盘“导出诊断包（离线）”导出，长行也保留在诊断包中。</p>
</template>
<style>.log-view{padding:8px 18px;max-height:65vh;overflow:auto}.log-line{display:grid;grid-template-columns:45px 1fr;gap:12px;padding:12px 0;border-bottom:1px solid var(--border);font-size:11px;line-height:1.8}.log-line>span{color:var(--muted);font-size:10px}.log-line code{white-space:pre-wrap;overflow-wrap:anywhere}.log-line.error>span{color:#e24747}.log-line.warn>span{color:#b87a12}.log-line.debug>span{color:#538bba}</style>
