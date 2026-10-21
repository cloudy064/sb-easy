<script setup lang="ts">
import { computed } from 'vue'
import { dailyMeasurement, type DailyIpEntry } from '../lib/ipcheck'
const props = defineProps<{ entry?: DailyIpEntry; local: boolean; unavailable: boolean }>()
const result = computed(() => dailyMeasurement(props.entry))
const fields = computed(() => (result.value?.ipv4?.ip_info || result.value?.ipv6?.ip_info)?.fields)
const label = computed(() => props.local ? '仅本机 · 中心未收录' : props.unavailable ? '中心结果暂不可用' : !props.entry ? '中心未收录此配置' :
  ({ ok:'已检测', failed:'刷新失败', pending:'等待自动检测', refreshing:'后台刷新中', disabled:'已停用', unsupported:'暂不支持' })[props.entry.status])
</script>

<template>
  <section class="node-ip-summary">
    <div class="ip-heading"><span>出口 IP</span><span :class="{ failed: entry?.status === 'failed' || unavailable }">{{ label }}</span></div>
    <template v-if="!local && (result?.ipv4?.ip || result?.ipv6?.ip)">
      <div class="ip-primary"><strong>{{ result?.ipv4?.ip || result?.ipv6?.ip }}</strong><span>{{ fields?.country_code || '地区未知' }}</span></div>
      <p>{{ fields?.asn || 'ASN 未知' }} · {{ fields?.organization || '运营商未知' }}</p>
      <p>IPv6：{{ result?.ipv6?.ip || '本次未测得出口' }}</p>
      <p v-if="fields?.privacy?.is_datacenter">数据中心网络 · 开源数据标记</p>
      <small v-if="result?.checked_at">{{ new Date(result.checked_at).toLocaleString() }}<span v-if="entry?.status === 'failed'"> · 上次成功结果</span></small>
    </template>
    <p v-else>{{ local ? '本机订阅不会上传到中心，也不会在后台切换本机代理。' : entry?.status === 'failed' ? '本次未能测得出口，后台将在下一周期重试。' : '中心每天自动检测，客户端直接读取结果。' }}</p>
  </section>
</template>

<style scoped>
.node-ip-summary { flex-basis:100%; min-width:0; padding-top:12px; margin-top:4px; border-top:1px solid var(--border); }
.ip-heading { display:flex; justify-content:space-between; gap:8px; color:var(--muted); font-size:10px; margin-bottom:9px; }
.ip-heading .failed { color:var(--error); }
.ip-primary { display:flex; align-items:center; gap:9px; flex-wrap:wrap; }
.ip-primary strong { font-family:Consolas,monospace; font-size:16px; font-weight:600; overflow-wrap:anywhere; }
.ip-primary span { padding:2px 6px; border-radius:4px; background:var(--accent-bg); color:var(--accent); font-size:10px; }
p { font-size:11px; line-height:1.5; color:var(--secondary); margin:6px 0 0; overflow-wrap:anywhere; }
small { display:block; margin-top:8px; color:var(--muted); font-size:10px; }
</style>
