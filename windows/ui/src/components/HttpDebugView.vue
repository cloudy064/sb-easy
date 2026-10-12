<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import type { NativeBridge } from '../lib/bridge'
import type { HttpDebugState } from '../lib/protocol'
const props = defineProps<{ bridge: NativeBridge }>()
const state = ref<HttpDebugState>({ phase: 'stopped', attached: false, error: '', url: '' })
const domains = ref(''), error = ref(''), busy = ref(false), trusted = ref(false)
let disposed = false, timer: ReturnType<typeof setTimeout> | undefined
async function refresh() {
  if (busy.value) { if (!disposed) timer = setTimeout(refresh, 2000); return }
  try { state.value = await props.bridge.request('httpdebug.snapshot'); if (state.value.attached) domains.value = (state.value.domains ?? []).join('\n') }
  catch (e) { error.value = String(e) }
  finally { if (!disposed) timer = setTimeout(refresh, 2000) }
}
async function action(method: 'httpdebug.start' | 'httpdebug.stop' | 'httpdebug.attach' | 'httpdebug.export' | 'httpdebug.open' | 'httpdebug.trust' | 'httpdebug.untrust') {
  busy.value = true; error.value = ''
  try {
    if (method === 'httpdebug.attach') state.value = await props.bridge.request(method, { domains: domains.value.split(/[\s,，]+/).filter(Boolean).map(d => d.toLowerCase()) }, { timeoutMs: 45_000 })
    else if (method === 'httpdebug.start' || method === 'httpdebug.stop') state.value = await props.bridge.request(method, {}, { timeoutMs: 45_000 })
    else { await props.bridge.request(method); if (method === 'httpdebug.trust' || method === 'httpdebug.untrust') trusted.value = method === 'httpdebug.trust' }
  } catch (e) { error.value = e instanceof Error ? e.message : String(e) }
  finally { busy.value = false }
}
onMounted(refresh); onUnmounted(() => { disposed = true; clearTimeout(timer) })
</script>
<template>
  <section class="debug-panel">
    <header><span class="eyebrow">POWERED BY MITMPROXY</span><h2>看清每一次请求</h2><p>HTTP(S) 明文会话 · 请求与响应 · 修改与重放</p></header>
    <p v-if="error || state.error" class="debug-error" role="alert">{{ error || state.error }}</p>
    <div class="step"><span class="number">1</span><div><h3>启动本机引擎</h3><p>会话仅保存在内存中，关闭引擎即清空。需要保留时，在会话窗口导出 HAR。</p><button :disabled="busy || state.phase === 'starting' || state.phase === 'running'" @click="action('httpdebug.start')">{{ state.phase === 'starting' ? '正在启动…' : state.phase === 'running' ? '引擎已就绪' : '启动引擎' }}</button></div></div>
    <div class="step"><span class="number">2</span><div><h3>信任抓包证书</h3><p>只为当前 Windows 用户安装本机生成的 CA。安装后重新打开目标应用；使用独立证书库或证书固定的应用仍可能拒绝连接。</p><button :disabled="busy || state.phase !== 'running'" @click="action('httpdebug.trust')">{{ trusted ? '已安装到当前用户' : '安装并信任证书' }}</button><button class="quiet" :disabled="busy || state.phase !== 'running'" @click="action('httpdebug.untrust')">移除这个证书</button></div></div>
    <div class="step"><span class="number">3</span><div><h3>选择抓包域名</h3><p>填写域名，以空格或换行分隔，包含其子域名。仅接管经过本机 TUN 或代理端口的这些域名的 HTTP/HTTPS；出口沿用原有域名分流。</p><textarea v-model="domains" :disabled="state.attached" placeholder="例如 api.example.com" rows="3" aria-label="抓包域名"/><p>开始和停止时会自动重载本地代理配置，现有连接可能重建。所选域名的 QUIC 会被拒绝，以便应用回退到 HTTPS/TCP。</p><button :disabled="busy || state.phase !== 'running' || state.attached || !domains.trim()" @click="action('httpdebug.attach')">{{ state.attached ? '正在抓取所选域名' : '开始抓包' }}</button></div></div>
    <footer><button class="primary" :disabled="busy || state.phase !== 'running'" @click="action('httpdebug.open')">打开会话窗口 ↗</button><button :disabled="busy || state.phase !== 'running'" @click="action('httpdebug.export')">导出 HAR</button><button :disabled="busy || state.phase === 'stopped' || state.phase === 'starting'" @click="action('httpdebug.stop')">停止并恢复普通代理</button></footer>
    <p class="footnote">会话窗口支持过滤、正文查看、编辑、断点、重放和导出。证书失败请查看其事件日志；没有会话不代表成功。超过 2 MB 的正文按流转发而不保留，单个消息上限 32 MB，最多保留约 500 个已完成会话。停止引擎不会自动移除证书。</p>
  </section>
</template>
<style scoped>
.debug-panel{max-width:920px;padding:28px;border:1px solid var(--border,#ddd);border-radius:20px;background:var(--surface,#fff);color:var(--ink,#182c2c)}header{margin-bottom:28px}.eyebrow{font-size:11px;letter-spacing:2px;color:#28796a}h2{font-size:30px;margin:10px 0}p{font-size:13px;line-height:1.8;opacity:.75}h3{margin:0;font-size:17px}.step{display:flex;gap:18px;padding:22px 0;border-top:1px solid #8883}.step>div{flex:1}.number{display:grid;place-items:center;width:30px;height:30px;flex-shrink:0;border-radius:50%;background:#28796a16;color:#28796a}button{border:1px solid #8885;border-radius:9px;background:transparent;color:inherit;padding:10px 16px;cursor:pointer;margin-right:8px}button:disabled{opacity:.45;cursor:default}.primary{background:#28796a;color:white;border-color:#28796a}.quiet{border:0}textarea{box-sizing:border-box;width:100%;padding:12px;background:transparent;color:inherit;border:1px solid #8885;border-radius:10px;font:inherit}footer{padding-top:20px;border-top:1px solid #8883}.footnote{font-size:12px;margin-top:20px}.debug-error{padding:12px;border-radius:10px;background:#c3333315;color:#bc3b3b}
</style>
