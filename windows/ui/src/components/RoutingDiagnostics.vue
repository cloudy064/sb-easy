<script setup lang="ts">
import { computed, ref } from 'vue'
import type { NativeBridge } from '../lib/bridge'
import type { RouteDelayResult, RouteProbeResult } from '../lib/protocol'
const props = defineProps<{ bridge: NativeBridge; connected: boolean; disabled: boolean; canProbe: boolean; canDelay: boolean; nodes: { tag: string; label?: string }[] }>()
const emit = defineEmits<{ busy: [value: boolean] }>()
const url = ref('https://www.gstatic.com/generate_204'), target = ref(''), pending = ref<'probe' | 'delay' | null>(null), error = ref('')
const probe = ref<RouteProbeResult | null>(null), delay = ref<RouteDelayResult | null>(null)
const unavailable = computed(() => props.disabled || !props.connected || pending.value !== null)
async function run(kind: 'probe' | 'delay') {
  if (unavailable.value || (kind === 'delay' && !target.value)) return
  pending.value = kind; error.value = ''; emit('busy', true)
  try {
    if (kind === 'probe') { probe.value = null; probe.value = await props.bridge.request('routing.probe', { url: url.value.trim(), timeout_ms: 10000 }, { timeoutMs: 25000 }) }
    else { delay.value = null; delay.value = await props.bridge.request('routing.delay', { target: target.value, url: url.value.trim(), timeout_ms: 5000 }, { timeoutMs: 15000 }) }
  } catch (failure) { error.value = failure instanceof Error ? failure.message : '测试失败，请检查服务日志。' }
  finally { pending.value = null; emit('busy', false) }
}
</script>
<template>
  <section class="panel routing-diagnostics" aria-labelledby="probe-title">
    <div class="section-heading"><div><h2 id="probe-title">网址路由测试与主动测速</h2><p class="input-hint">从本机服务发出真实请求，通过当前内核验证连接。测试请求不会携带浏览器登录信息。</p></div></div>
    <p v-if="!connected" class="input-hint">连接后可以运行测试。</p>
    <label class="probe-field" for="probe-url">测试网址<input id="probe-url" v-model="url" type="url" placeholder="https://example.com/" :disabled="unavailable" /></label>
    <div class="probe-controls"><button class="primary-button" :disabled="unavailable || !canProbe || !url.trim()" @click="run('probe')">{{ pending === 'probe' ? '正在请求…' : '测试当前路由' }}</button><label for="delay-target">测速节点</label><select id="delay-target" v-model="target" :disabled="unavailable"><option value="" disabled>选择节点或策略组</option><option v-for="item in nodes" :key="item.tag" :value="item.tag">{{ item.label || item.tag }}</option></select><button class="secondary-button" :disabled="unavailable || !canDelay || !target || !url.trim()" @click="run('delay')">{{ pending === 'delay' ? '测速中…' : '开始测速' }}</button></div>
    <p v-if="error" class="diagnostic-error" role="alert">{{ error }}</p>
    <div v-if="delay" class="probe-summary" role="status"><strong>{{ delay.target }}</strong><span>{{ delay.delay_ms }} ms</span><small>本次主动测试 · 不改变节点选择</small></div>
    <div v-if="probe" class="probe-result" role="status">
      <div class="probe-summary"><strong>{{ probe.success ? '请求成功' : '请求失败' }}</strong><span>{{ probe.elapsed_ms }} ms</span><span>{{ probe.http_status ? `HTTP ${probe.http_status}` : '未收到 HTTP 响应' }}</span><code v-if="probe.error_code">{{ probe.error_code }}</code></div>
      <dl class="diagnostic-list"><div><dt>目标</dt><dd>{{ probe.host }}:{{ probe.port }}</dd></div><div><dt>命中规则</dt><dd>{{ probe.evidence.connection?.rule || '本次连接未采集到规则' }}</dd></div><div><dt>选择链</dt><dd>{{ probe.evidence.connection?.chains.join(' → ') || '未观测到' }}</dd></div><div><dt>目标地址</dt><dd>{{ probe.evidence.connection?.metadata.destinationIP || '未观测到' }}</dd></div><div><dt>DNS 模式</dt><dd>{{ probe.evidence.connection?.metadata.dnsMode || '未单独观测到 DNS 请求' }}</dd></div><div><dt>公网出口 IP</dt><dd>此探测未检测</dd></div></dl>
      <p class="input-hint">这是服务自身发出的测试流量；应用专属进程规则请在“活动连接”中查看对应应用。短连接可能在采样前结束，缺失证据不会推断为直连。</p>
      <details v-if="probe.evidence.logs.length"><summary>本次关联日志</summary><pre>{{ probe.evidence.logs.join('\n') }}</pre></details>
    </div>
  </section>
</template>
<style scoped>
.routing-diagnostics{padding:22px;margin-bottom:20px}.probe-field{display:grid;gap:8px;font-size:13px}.probe-field input,.probe-controls select{padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--ink);min-width:0}.probe-controls{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:16px 0}.probe-controls select{flex:1;min-width:170px}.probe-controls label{font-size:12px}.probe-summary{display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:15px 0;color:var(--secondary)}.probe-summary strong{color:var(--ink)}.probe-summary small{color:var(--muted)}.probe-result pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:260px;overflow:auto;font-size:11px}
</style>
