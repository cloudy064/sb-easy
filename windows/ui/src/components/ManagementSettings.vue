<script setup lang="ts">
import { ref, watch } from 'vue'
import type { ManagementSettings, ManagementStatus } from '../lib/protocol'
const props = defineProps<{ value?: ManagementStatus; disabled: boolean; pending: boolean }>()
const emit = defineEmits<{ change: [settings: Partial<ManagementSettings>] }>()
const interval = ref(30)
watch(() => props.value?.sync_interval_seconds, value => { if (value !== undefined) interval.value = value }, { immediate: true })
function time(value: number) { return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '尚未成功' }
</script>
<template>
  <section class="panel settings-panel" aria-labelledby="management-title">
    <div class="section-heading"><h2 id="management-title">后台管理与连接恢复</h2><span class="status-tag">{{ value?.worker_running ? '后台运行中' : '等待后台服务' }}</span></div>
    <p class="input-hint">中心同步与连接恢复由 Windows 服务执行，关闭窗口后仍继续运行。</p>
    <template v-if="value">
      <p v-if="value.kill_switch_recovery_required" class="diagnostic-error" role="alert">检测到现有防泄漏规则，但本机保存的选择已丢失或无效。阻断会保留，请明确开启防泄漏或点击“解除现有阻断”。</p>
      <div class="setting-row"><div><h3>服务启动后自动连接</h3><p>使用本机已有配置。手动断开会暂停自动连接，直到再次点击连接。</p></div><button class="toggle" role="switch" aria-label="服务启动后自动连接" :aria-checked="value.auto_connect" :class="{ enabled: value.auto_connect }" :disabled="disabled" @click="emit('change', { auto_connect: !value.auto_connect })"><span /></button></div>
      <div class="setting-row"><div><h3>自动恢复连接</h3><p>核心退出、网络变化或休眠恢复后重试；连续失败时逐步延长至 60 秒。</p></div><button class="toggle" role="switch" aria-label="自动恢复连接" :aria-checked="value.auto_reconnect" :class="{ enabled: value.auto_reconnect }" :disabled="disabled" @click="emit('change', { auto_reconnect: !value.auto_reconnect })"><span /></button></div>
      <div v-if="value.kill_switch_enabled !== undefined" class="setting-row"><div><h3>断线防泄漏</h3><p>开启后立即阻止普通应用绕过代理直连（IPv4 / IPv6）。手动断开、内核或服务退出后仍生效，关闭此开关才解除。需要管理员服务权限。</p></div><button class="toggle" role="switch" aria-label="断线防泄漏" :aria-checked="value.kill_switch_enabled" :class="{ enabled: value.kill_switch_enabled }" :disabled="disabled" @click="emit('change', { kill_switch_enabled: !value.kill_switch_enabled })"><span /></button></div>
      <template v-if="value.kill_switch"><div class="environment-row"><span>防泄漏规则</span><strong>{{ !value.kill_switch.available ? '无法读取系统防火墙' : value.kill_switch.enabled ? `阻断已生效 · ${value.kill_switch.filter_count} 条规则` : '未启用' }}</strong></div><p v-if="value.kill_switch.error_code" class="diagnostic-error" role="alert">系统规则状态：{{ value.kill_switch.error_code }}</p><p v-if="value.kill_switch.enabled" class="input-hint">允许本机回环、代理内核、管理服务、TUN 和必要的地址配置流量。断线时若中心域名没有缓存，系统 DNS 可能无法解析；可关闭此开关恢复普通联网。</p><button v-if="value.kill_switch.enabled && !value.kill_switch_enabled" class="secondary-button" :disabled="disabled" @click="emit('change', { kill_switch_enabled: false })">解除现有阻断</button></template>
      <div class="setting-row"><div><h3>向中心报告流量汇总</h3><p>仅发送速率、累计流量和连接数量，不发送访问域名、进程或日志。</p></div><button class="toggle" role="switch" aria-label="向中心报告流量汇总" :aria-checked="value.telemetry_enabled" :class="{ enabled: value.telemetry_enabled }" :disabled="disabled" @click="emit('change', { telemetry_enabled: !value.telemetry_enabled })"><span /></button></div>
      <form class="setting-row" @submit.prevent="emit('change', { sync_interval_seconds: interval })"><label for="management-interval"><h3>同步与心跳间隔</h3><p>配置、设备状态和中心命令共用此间隔，15–3600 秒。</p></label><div class="management-interval"><input id="management-interval" v-model.number="interval" type="number" min="15" max="3600" step="1" required :disabled="disabled" /><span>秒</span><button class="secondary-button" :disabled="disabled || interval === value.sync_interval_seconds">{{ pending ? '保存中…' : '保存' }}</button></div></form>
      <div class="environment-row"><span>最近同步</span><strong>{{ time(value.last_sync_at) }}</strong></div>
      <div class="environment-row"><span>最近状态上报</span><strong>{{ time(value.last_report_at) }}</strong></div>
      <p v-if="value.manual_disconnect" class="input-hint" role="status">已手动断开，自动连接已暂停。点击首页“连接”后恢复。</p>
      <p v-else-if="value.desired_connected && value.retry_attempt" class="input-hint" role="status">已重试 {{ value.retry_attempt }} 次，{{ value.retry_in_seconds ? `${value.retry_in_seconds} 秒后重试` : '等待下一次检查' }}。</p>
      <p v-if="value.last_error" class="diagnostic-error" role="alert">{{ value.last_error }} <code>{{ value.last_error_code }}</code></p>
    </template>
    <p v-else class="input-hint">此服务版本尚未提供后台管理设置。</p>
  </section>
</template>
<style scoped>
.management-interval{display:flex;align-items:center;gap:8px}.management-interval input{width:88px;padding:8px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--ink)}
</style>
