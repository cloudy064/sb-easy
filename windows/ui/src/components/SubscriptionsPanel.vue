<script setup lang="ts">
import { ref } from 'vue'
import { bytes } from '../lib/dashboard'
import type { SubscriptionImport, SubscriptionsSummary } from '../lib/protocol'
defineProps<{ summary?: SubscriptionsSummary; disabled: boolean; filter: string; busy: boolean; independent?: boolean }>()
const emit = defineEmits<{ add: [input: SubscriptionImport]; refresh: [id: string]; remove: [id: string]; filter: [value: string] }>()
const adding = ref(false), name = ref(''), url = ref(''), body = ref(''), removing = ref('')
const kind = ref<'url' | 'body'>('url'), interval = ref(360)
function submit() {
  if (!name.value.trim() || !(kind.value === 'url' ? url.value.trim() : body.value.trim())) return
  emit('add', { name: name.value.trim(), ...(kind.value === 'url' ? { url: url.value.trim(), refresh_interval_minutes: interval.value } : { body: body.value }) })
  url.value = ''; body.value = ''
}
function when(seconds: number | undefined) { return seconds ? new Date(seconds * 1000).toLocaleString('zh-CN', { hour12: false }) : '尚无记录' }
const reasons: Record<string, string> = {
  unsupported_protocol_or_unsafe_parameters: '协议不支持或包含不安全参数', duplicate_name_renamed: '重名节点已自动改名',
  routing_dns_and_inbounds_not_imported: '仅提取节点；路由、DNS 和入站未导入', routing_dns_and_scripts_not_imported: '仅提取节点；路由、DNS 和脚本未导入',
  unsupported_yaml_entry: '不支持的 YAML 节点', unsupported_uri_or_invalid_parameters: '不支持的分享链接或参数无效', node_limit_reached: '超出 256 个节点上限',
}
</script>
<template>
  <section class="subscriptions-panel panel">
    <div class="section-heading"><div><h2>订阅来源</h2><p class="routing-subtitle">{{ independent ? '独立模式：订阅和规则保存在这台电脑，后台服务负责更新。' : '服务器订阅由共享配置管理。本机订阅只在这台电脑使用。' }}</p></div><button class="secondary-button" :disabled="disabled" @click="adding = !adding">{{ adding ? '收起' : '+ 添加本机订阅' }}</button></div>
    <form v-if="adding" class="subscription-form" @submit.prevent="submit">
      <label>订阅名称<input v-model="name" maxlength="100" required :disabled="disabled" placeholder="例如：备用线路" /></label>
      <label>导入方式<select v-model="kind" :disabled="disabled"><option value="url">订阅地址</option><option value="body">粘贴离线内容</option></select></label>
      <template v-if="kind === 'url'"><label>订阅地址<input v-model="url" type="url" required maxlength="8192" autocomplete="off" :spellcheck="false" :disabled="disabled" placeholder="https://…" /></label><label>后台更新<select v-model.number="interval" :disabled="disabled"><option :value="0">仅手动更新</option><option :value="15">每 15 分钟</option><option :value="60">每小时</option><option :value="360">每 6 小时</option><option :value="1440">每天</option></select></label></template>
      <label v-else>订阅内容<textarea v-model="body" rows="7" required maxlength="262144" autocomplete="off" :spellcheck="false" :disabled="disabled" placeholder="粘贴分享链接、Clash YAML 或 sing-box JSON" /></label>
      <p>支持 Clash YAML、sing-box JSON、Base64 或明文分享链接。导入报告会显示跳过的节点；只导入节点，不导入路由、DNS 或脚本。运行中修改订阅会重新加载内核，连接可能短暂中断。</p>
      <button class="primary-button" :disabled="disabled || !name.trim() || !(kind === 'url' ? url.trim() : body.trim())">{{ busy ? '正在处理…' : kind === 'url' ? '下载并添加' : '导入内容' }}</button>
    </form>
    <div class="subscription-filters"><button class="source-choice" :class="{ selected: !filter }" @click="emit('filter', '')">全部节点</button><button class="source-choice" :class="{ selected: filter === 'unknown' }" @click="emit('filter', 'unknown')">其他 / 未知来源</button></div>
    <p v-if="!independent && summary?.managed.length && !summary.sources_available" class="collection-note">服务器尚未提供订阅归属。</p>
    <div class="subscription-grid">
      <article v-for="sub in summary?.managed ?? []" :key="`managed-${sub.id}`" class="subscription-source" :class="{ selected: filter === `managed:${sub.id}` }"><button @click="emit('filter', `managed:${sub.id}`)"><strong>{{ sub.name }}</strong><span>服务器订阅 · {{ sub.tags.length }} 个节点</span></button></article>
      <article v-for="sub in summary?.local ?? []" :key="`local-${sub.id}`" class="subscription-source" :class="{ selected: filter === `local:${sub.id}` }">
        <button @click="emit('filter', `local:${sub.id}`)"><strong>{{ sub.name }}</strong><span>{{ sub.remote ? '本机订阅' : '离线导入' }} · {{ sub.tags.length }} 个节点</span></button>
        <div class="subscription-health"><p>最近成功：{{ when(sub.last_success_at) }}</p><p v-if="sub.remote">{{ sub.refresh_interval_minutes ? `每 ${sub.refresh_interval_minutes} 分钟更新，下次：${when(sub.next_refresh_at)}` : '仅手动更新' }}</p><p v-if="sub.last_error" role="alert">上次更新失败：{{ sub.last_error }}；保留已保存的节点。</p>
          <template v-if="sub.metadata?.available"><p>已用 {{ bytes(sub.metadata.used_bytes) }} · {{ sub.metadata.total_bytes === 0 ? '不限流量' : sub.metadata.total_bytes === undefined ? '总量未提供' : `总量 ${bytes(sub.metadata.total_bytes)}，剩余 ${bytes(sub.metadata.remaining_bytes)}` }}</p><p>{{ sub.metadata.expires_at === 0 ? '无到期时间' : sub.metadata.expires_at ? `到期：${when(sub.metadata.expires_at)}` : '到期时间未提供' }}<strong v-if="sub.metadata.expired"> · 已到期</strong><strong v-if="sub.metadata.quota_exhausted"> · 流量已用完</strong></p></template>
          <p v-else>{{ sub.metadata?.header_present ? '订阅流量信息格式无效' : '订阅未提供流量和到期信息' }}</p>
        </div>
        <details v-if="sub.report?.format" class="subscription-report"><summary>导入报告：{{ sub.report.imported }} 个可用，{{ sub.report.skipped }} 个跳过</summary><p>{{ sub.report.format }}{{ sub.report.base64 ? ' · Base64' : '' }}</p><ul v-if="sub.report.warnings?.length"><li v-for="(warning, index) in sub.report.warnings" :key="index">{{ warning.position ? `第 ${warning.position} 项：` : '' }}{{ reasons[warning.reason] ?? warning.reason }}</li></ul><p v-else>所有节点均通过格式检查。</p></details>
        <div class="subscription-actions"><button v-if="sub.remote !== false" class="text-button" :disabled="disabled" @click="emit('refresh', sub.id)">更新</button><button class="text-button" :disabled="disabled" @click="removing = sub.id">删除</button></div>
        <div v-if="removing === sub.id" class="subscription-confirm"><p>删除本机订阅及其节点？正在使用的节点需先切换到其他出口。</p><button class="text-button" :disabled="disabled" @click="emit('remove', sub.id); removing = ''">确认删除</button><button class="text-button" @click="removing = ''">取消</button></div>
      </article>
    </div>
    <p v-if="!summary?.local.length" class="collection-note">还没有本机订阅。添加后可在“连接”页面选择节点；首次导入即可使用独立模式。</p>
  </section>
</template>
