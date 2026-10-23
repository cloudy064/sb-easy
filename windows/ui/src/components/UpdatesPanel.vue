<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import type { NativeBridge } from '../lib/bridge'
import type { UpdatePhase, UpdateStatus } from '../lib/protocol'
const props = defineProps<{ bridge: NativeBridge; disabled: boolean }>()
const emit = defineEmits<{ busy: [value: boolean] }>()
const status = ref<UpdateStatus>(), source = ref(''), notice = ref(''), failed = ref(false), pending = ref(false), confirmInstall = ref(false)
const phaseLabels: Record<UpdatePhase, string> = {
  unavailable: '此安装暂不支持更新', idle: '尚未检查', checking: '正在验证发布清单', available: '有可用更新', current: '当前已是此清单的最新版本',
  deferred: '尚未轮到此电脑的分批发布', downloading: '正在下载并验证安装包', ready: '安装包验证通过', installing: '正在安装与检查新版本',
  succeeded: '升级完成', rolled_back: '升级失败，已恢复旧版本与配置', failed: '更新未完成', cancelled: '已取消', recovery_required: '上次升级需要恢复',
}
const phase = computed(() => status.value?.phase ?? 'idle')
const active = computed(() => status.value?.busy === true || phase.value === 'installing' || phase.value === 'recovery_required')
const percent = computed(() => status.value?.release?.bytes ? Math.min(100, Math.floor(status.value.received_bytes / status.value.release.bytes * 100)) : 0)
const formatSize = (bytes: number) => `${(bytes / 1024 / 1024).toFixed(1)} MiB`
let timer: ReturnType<typeof setTimeout> | undefined, alive = true, loading = false
async function refresh() {
  if (!alive || loading || pending.value) return
  loading = true
  try { const next = await props.bridge.request('updates.status', {}, { timeoutMs: 15000 }); if (alive) status.value = next }
  catch (error) { if (alive) { notice.value = error instanceof Error ? error.message : '无法读取更新状态。'; failed.value = true } }
  finally { loading = false }
}
function schedule() {
  timer = setTimeout(async () => { await refresh(); if (alive) schedule() }, active.value ? 2000 : 15000)
}
async function action(task: () => Promise<UpdateStatus>) {
  if (pending.value || props.disabled) return
  pending.value = true; emit('busy', true); notice.value = ''; failed.value = false
  try { status.value = await task(); confirmInstall.value = false }
  catch (error) { failed.value = true; notice.value = error instanceof Error ? error.message : '更新操作未完成。' }
  finally { pending.value = false; if (alive) { emit('busy', false); if (timer) clearTimeout(timer); schedule() } }
}
const check = () => action(() => props.bridge.request('updates.check', { manifest_url: source.value.trim() }))
const download = () => status.value?.release && action(() => props.bridge.request('updates.download', { release_id: status.value!.release!.id }))
const install = () => status.value?.release && action(() => props.bridge.request('updates.install', { release_id: status.value!.release!.id }, { timeoutMs: 90000 }))
const cancel = () => action(() => props.bridge.request('updates.cancel', {}))
const recover = () => action(() => props.bridge.request('updates.recover', {}, { timeoutMs: 45000 }))
onMounted(async () => { await refresh(); if (alive) schedule() })
onBeforeUnmount(() => { alive = false; if (timer) clearTimeout(timer) })
</script>

<template>
  <section class="panel updates-panel" aria-labelledby="updates-title">
    <div class="section-heading"><h2 id="updates-title">应用与内核更新</h2><span class="status-tag" :class="{ pending: !['ready', 'succeeded', 'current'].includes(phase) }">{{ phaseLabels[phase] }}</span></div>
    <p class="input-hint">应用与 sing-box 作为同一安装包升级。发布者签名、安装包内容和版本匹配检查通过后才可安装；新版本启动检查失败时恢复旧版本与加密配置。</p>
    <p v-if="status" class="update-versions">当前应用 <strong>{{ status.current_version }}</strong><span>·</span>内核 <strong>{{ status.current_core_version }}</strong></p>
    <p v-if="status && !status.publisher_configured" class="input-hint" data-testid="updates-unconfigured">此开发版尚未配置可信发布者。安装正式签名的 MSI 后才能使用更新。</p>
    <p v-else-if="status && !status.installed_service" class="input-hint">自动更新需要通过 MSI 安装的后台服务。便携版可手动安装正式版本。</p>
    <form class="updates-source" @submit.prevent="check"><label>发布清单地址<input v-model="source" type="url" required placeholder="https://downloads.example.com/windows/release.json" :disabled="disabled || !status?.supported || active" aria-label="HTTPS 发布清单地址" /></label><button class="secondary-button" :disabled="disabled || !status?.supported || active || !source" data-testid="updates-check">检查签名更新</button></form>
    <p class="input-hint">使用发布方提供的 HTTPS 清单直链。下载源不能更改本机已信任的发布者，也不会自动下载安装。</p>
    <div v-if="status?.release" class="update-release"><div><strong>应用 {{ status.release.version }}</strong><span>内核 {{ status.release.core_version }} · 稳定版 · {{ formatSize(status.release.bytes) }}</span></div><p v-if="phase === 'deferred'" class="input-hint">此版本发布范围为 {{ status.release.rollout_percent }}%，本机将等待后续发布范围扩大。</p><div v-if="phase === 'downloading'" class="update-progress"><progress :value="status.received_bytes" :max="status.release.bytes" aria-label="安装包下载进度" /><span>{{ percent }}% · {{ formatSize(status.received_bytes) }}</span></div><div class="update-actions"><button v-if="phase === 'available'" class="secondary-button" :disabled="disabled" @click="download" data-testid="updates-download">下载并验证安装包</button><button v-if="phase === 'ready' && !confirmInstall" class="primary-button" :disabled="disabled" @click="confirmInstall = true" data-testid="updates-install-review">安装此版本</button><button v-if="status.cancellable" class="text-button" :disabled="disabled" @click="cancel" data-testid="updates-cancel">取消检查或下载</button></div></div>
    <div v-if="confirmInstall && phase === 'ready'" class="update-confirm" role="region" aria-label="安装更新确认"><h3>确认安装更新</h3><p>窗口将关闭，代理连接会暂时中断。服务会备份当前加密配置，安装后检查新版本，并在之前已连接时重新连接。完成后请重新打开 sb-easy 查看结果。</p><div class="update-actions"><button class="primary-button" :disabled="disabled" @click="install" data-testid="updates-install">确认安装并关闭窗口</button><button class="text-button" :disabled="disabled" @click="confirmInstall = false">暂不安装</button></div></div>
    <p v-if="phase === 'installing'" class="input-hint">安装事务正在进行，暂时不能修改设备配置或取消安装。完成后重新打开客户端查看结果。</p>
    <div v-if="phase === 'recovery_required'" class="update-confirm"><h3>恢复上次升级</h3><p>加密配置备份已保留。恢复助手会核对已安装版本和安装事务状态，恢复完成前不会覆盖未知状态。</p><button class="secondary-button" :disabled="disabled" @click="recover" data-testid="updates-recover">重试安全恢复</button></div>
    <p v-if="status?.last_result?.reboot_required" class="input-hint">Windows 安装程序报告需要重新启动电脑，请保存工作后重启。</p>
    <p v-if="status?.error && !['current', 'deferred', 'unavailable'].includes(phase)" class="diagnostic-error" role="alert">{{ status.error.message }}（{{ status.error.code }}）</p>
    <p v-if="notice" :class="failed ? 'diagnostic-error' : 'input-hint'" :role="failed ? 'alert' : 'status'">{{ notice }}</p>
  </section>
</template>

<style scoped>
.updates-panel { margin-top:24px; padding:24px; }.update-versions { display:flex; align-items:center; flex-wrap:wrap; gap:9px; color:var(--secondary); font-size:13px; }.update-versions strong { color:var(--ink); font-weight:550; }.updates-source { display:flex; align-items:end; gap:12px; margin-top:18px; flex-wrap:wrap; }.updates-source label { display:grid; gap:7px; font-size:12px; color:var(--secondary); flex:1; min-width:220px; }.updates-source input { width:100%; box-sizing:border-box; padding:10px; border:1px solid var(--border); border-radius:8px; background:var(--paper); color:var(--ink); }.update-release { border-top:1px solid var(--border); margin-top:20px; padding-top:18px; }.update-release>div:first-child { display:flex; gap:14px; flex-wrap:wrap; align-items:center; font-size:13px; }.update-release span { color:var(--secondary); }.update-actions { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-top:14px; }.update-progress { display:flex; align-items:center; gap:12px; margin-top:14px; font-size:12px; }.update-progress progress { flex:1; accent-color:var(--accent); }.update-confirm { padding:18px; margin-top:18px; border:1px solid var(--accent); background:var(--accent-bg); border-radius:10px; font-size:13px; line-height:1.7; }.update-confirm h3 { margin:0; font-size:14px; }
</style>
