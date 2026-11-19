<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import type { NativeBridge } from '../lib/bridge'
import type { TailscaleStatus } from '../lib/protocol'
import { tailscaleDisplay, tailscaleEndpointDisplay } from '../lib/tailscale'

const props = defineProps<{
  bridge: NativeBridge; supported: boolean; connected: boolean; running: boolean
  disabled: boolean; autoRefresh: boolean; revision: string
}>()
const snapshot = ref<TailscaleStatus | null>(null)
const pending = ref(false)
const issue = ref('')
const copied = ref('')
const copyIssue = ref('')
const checkedAt = ref<Date | null>(null)
const display = computed(() => tailscaleDisplay(snapshot.value, {
  supported: props.supported, connected: props.connected, running: props.running, issue: issue.value, pending: pending.value,
}))
const endpoints = computed(() => props.connected && props.running && !issue.value && snapshot.value?.available && snapshot.value.active ? snapshot.value.endpoints : [])
let timer: ReturnType<typeof setTimeout> | undefined
let mounted = false, alive = true, generation = 0

function invalidate() {
  ++generation
  snapshot.value = null
  checkedAt.value = null
  issue.value = ''
  copied.value = ''
  copyIssue.value = ''
}
async function refresh() {
  if (!alive || pending.value || props.disabled || !props.supported || !props.connected || document.visibilityState !== 'visible') return
  pending.value = true
  const requestGeneration = generation
  try {
    const next = await props.bridge.request('tailscale.status', {}, { timeoutMs: 6000 })
    if (alive && requestGeneration === generation) {
      snapshot.value = next
      issue.value = ''
      checkedAt.value = new Date()
    }
  } catch (error) {
    if (alive && requestGeneration === generation) {
      snapshot.value = null
      checkedAt.value = null
      issue.value = error instanceof Error ? error.message : '无法读取 Tailscale 状态，请稍后刷新。'
    }
  } finally {
    pending.value = false
    if (alive && requestGeneration !== generation && mounted) void refresh()
  }
}
function schedule() {
  timer = setTimeout(async () => {
    if (props.autoRefresh) await refresh()
    if (alive) schedule()
  }, 10000)
}
function visibilityChanged() {
  // A hidden tab must not reappear with an old online indication.
  invalidate()
  if (document.visibilityState === 'visible' && props.autoRefresh) void refresh()
}
async function copyAddress(address: string) {
  copied.value = ''; copyIssue.value = ''
  try { await navigator.clipboard.writeText(address); if (alive) copied.value = address }
  catch { if (alive) copyIssue.value = '无法自动复制，请选中地址手动复制。' }
}
watch(() => [props.supported, props.connected, props.running, props.revision], () => {
  invalidate()
  if (mounted) void refresh()
})
watch(() => props.disabled, disabled => { if (!disabled && mounted && !snapshot.value) void refresh() })
onMounted(() => {
  mounted = true
  void refresh()
  schedule()
  document.addEventListener('visibilitychange', visibilityChanged)
})
onBeforeUnmount(() => {
  alive = false; ++generation
  clearTimeout(timer)
  document.removeEventListener('visibilitychange', visibilityChanged)
})
</script>

<template>
  <section class="panel tailscale-panel" aria-labelledby="tailscale-title" data-testid="tailscale-panel">
    <div class="section-heading">
      <div class="tailscale-heading"><h2 id="tailscale-title">Tailscale</h2><span class="status-tag" :class="{ pending: display.tone !== 'ready' }" role="status" data-testid="tailscale-state"><span class="state-dot" :class="{ ready: display.tone === 'ready' }" />{{ display.label }}</span></div>
      <button class="text-button" :disabled="disabled || pending || !supported || !connected" @click="refresh" data-testid="tailscale-refresh">{{ pending ? '读取中…' : '刷新状态' }}</button>
    </div>
    <p class="input-hint" :class="{ 'tailscale-warning': display.tone === 'warning' }" data-testid="tailscale-detail">{{ display.detail }}</p>
    <div v-if="snapshot" class="tailscale-sync" aria-label="Tailscale 配置状态"><span>本机配置：<strong>{{ snapshot.configured ? '已同步' : '未启用' }}</strong></span><span>当前运行：<strong>{{ snapshot.active && running ? '已加载' : '未加载' }}</strong></span></div>
    <p v-if="snapshot?.active && !snapshot.configured" class="input-hint">中央配置已停用 Tailscale，当前连接仍使用上次配置；应用新配置后生效。</p>
    <article v-for="endpoint in endpoints" :key="endpoint.tag" class="tailscale-device" data-testid="tailscale-device">
      <div class="tailscale-device-heading"><h3>{{ endpoint.self?.hostname || '本机设备' }}</h3><span v-if="endpoints.length > 1" class="status-tag" :class="{ pending: tailscaleEndpointDisplay(endpoint).tone !== 'ready' }">{{ tailscaleEndpointDisplay(endpoint).label }}</span></div>
      <dl class="tailscale-details">
        <div><dt>网络</dt><dd>{{ endpoint.network_name || '尚未获取' }}</dd></div>
        <div v-if="endpoint.self?.dns_name"><dt>设备域名</dt><dd>{{ endpoint.self.dns_name }}</dd></div>
        <div><dt>Tailscale 地址</dt><dd><ul v-if="endpoint.self?.ips.length" class="tailscale-addresses"><li v-for="address in endpoint.self.ips" :key="address"><code>{{ address }}</code><button class="text-button" :aria-label="`复制 Tailscale 地址 ${address}`" @click="copyAddress(address)">{{ copied === address ? '已复制' : '复制' }}</button></li></ul><span v-else>尚未分配</span></dd></div>
      </dl>
      <p v-if="endpoints.length > 1 && tailscaleEndpointDisplay(endpoint).tone !== 'ready'" class="input-hint">{{ tailscaleEndpointDisplay(endpoint).detail }}</p>
    </article>
    <p v-if="copyIssue" class="input-hint" role="status">{{ copyIssue }}</p>
    <div class="tailscale-footer"><span>在中央面板的“设备 → 编辑”中管理 Tailscale 配置。</span><span v-if="checkedAt">更新于 {{ checkedAt.toLocaleTimeString('zh-CN', { hour12: false }) }}</span></div>
    <p v-if="display.tone === 'ready'" class="input-hint tailscale-address-note">测试互联时请使用 Tailscale 地址。</p>
  </section>
</template>

<style scoped>
.tailscale-panel{margin:24px 0;padding:24px}.tailscale-heading,.tailscale-device-heading{display:flex;align-items:center;gap:14px;flex-wrap:wrap}.tailscale-heading h2,.tailscale-device-heading h3{margin:0}.tailscale-sync{display:flex;gap:24px;flex-wrap:wrap;margin-top:16px;font-size:12px;color:var(--secondary)}.tailscale-sync strong{font-weight:550;color:var(--ink)}.tailscale-device{margin-top:18px;padding-top:18px;border-top:1px solid var(--border)}.tailscale-device-heading h3{font-size:14px;font-weight:600;overflow-wrap:anywhere}.tailscale-details{display:grid;gap:13px;margin:18px 0 0;font-size:13px}.tailscale-details>div{display:grid;grid-template-columns:110px minmax(0,1fr);gap:16px}.tailscale-details dt{color:var(--secondary)}.tailscale-details dd{margin:0;overflow-wrap:anywhere}.tailscale-addresses{list-style:none;padding:0;margin:0;display:grid;gap:7px}.tailscale-addresses li{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.tailscale-addresses code{font-size:12px;user-select:all;overflow-wrap:anywhere}.tailscale-addresses button{font-size:12px}.tailscale-footer{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:18px;color:var(--secondary);font-size:12px;line-height:1.7}.tailscale-address-note{margin-bottom:0}.tailscale-warning{color:var(--ink)}@media(max-width:600px){.tailscale-panel{padding:18px}.tailscale-details>div{grid-template-columns:1fr;gap:5px}.tailscale-heading{gap:9px}}
</style>
