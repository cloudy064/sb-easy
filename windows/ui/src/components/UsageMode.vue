<script setup lang="ts">
import type { UsageMode } from '../lib/protocol'
defineProps<{ mode: UsageMode; disabled: boolean; running: boolean; managedAvailable: boolean; independentAvailable: boolean }>()
const emit = defineEmits<{ change: [mode: 'managed' | 'independent']; import: [] }>()
</script>
<template>
  <section class="panel mode-panel" aria-labelledby="usage-mode-title">
    <div class="section-heading"><h2 id="usage-mode-title">使用模式</h2><span class="status-tag">{{ mode === 'managed' ? '中心受管' : mode === 'independent' ? '本机独立' : '尚未配置' }}</span></div>
    <div class="usage-mode-options"><div><h3>独立使用</h3><p>直接导入订阅或分享链接，配置保存在此电脑。已有节点可离线启动。</p><button class="secondary-button" :disabled="disabled || running || mode === 'independent'" @click="emit('change', 'independent')">{{ independentAvailable ? '切换到独立配置' : '启用独立模式' }}</button><button v-if="mode === 'independent' || mode === 'unconfigured'" class="text-button" :disabled="disabled" @click="emit('import')">导入本机订阅 →</button></div><div><h3>中心受管</h3><p>由管理中心分发配置、监控状态和执行命令，本机仍可添加节点与分流。</p><button class="secondary-button" :disabled="disabled || running || mode === 'managed'" @click="emit('change', 'managed')">{{ managedAvailable ? '恢复受管配置' : '连接管理中心' }}</button></div></div>
    <p class="input-hint">{{ running ? '先断开连接，再切换模式。' : '切换时保留两种模式的配置和凭据，不会自动连接。' }}</p>
  </section>
</template>
<style scoped>
.mode-panel{padding:22px;margin-bottom:20px}.usage-mode-options{display:grid;grid-template-columns:1fr 1fr;gap:24px}.usage-mode-options h3{font-size:14px}.usage-mode-options p{font-size:12px;color:var(--secondary);line-height:1.7;margin:8px 0 12px}.usage-mode-options .text-button{display:block;margin-top:10px}@media(max-width:720px){.usage-mode-options{grid-template-columns:1fr}}
</style>
