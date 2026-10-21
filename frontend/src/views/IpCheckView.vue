<script setup lang="ts">
import { onMounted, ref, computed } from 'vue'
import IpCheckView from '../../../windows/ui/src/components/IpCheckView.vue'
import type { NativeBridge } from '../../../windows/ui/src/lib/bridge'
import { validResult } from '../../../windows/ui/src/lib/protocol'
import client from '../api/client'
const hosts=ref<{id:string;name:string;profile_id?:string}[]>([]), selected=ref(''), error=ref('')
const bridge=computed(() => {
  const id=selected.value
  return {async request(method:string,params:unknown={}) {
    if(!['ipcheck.catalog','ipcheck.start','ipcheck.snapshot','ipcheck.cancel'].includes(method))throw new Error('不支持的检测操作')
    try {
      const {data}=await client.post(`/hosts/${encodeURIComponent(id)}/ipcheck/${method.slice(8)}`,params)
      if(!validResult(method as 'ipcheck.snapshot',data))throw new Error('中心检测返回格式无效')
      return data
    } catch(cause) { throw new Error((cause as {response?:{data?:{error?:string}}}).response?.data?.error || '中心检测暂不可用，请检查服务状态') }
  }} as NativeBridge
})
onMounted(async()=>{try {hosts.value=(await client.get('/hosts')).data;selected.value=hosts.value[0]?.id??''}catch{error.value='无法读取中心配置'}})
</script>
<template>
  <div class="page-header"><h2>IP 检测</h2><p class="text-muted">中心服务器执行检测，按设备对应的配置选择节点；同一配置共享结果。</p></div>
  <label>选择配置来源 <select v-model="selected"><option v-for="host in hosts" :key="host.id" :value="host.id">{{ host.name }} · {{ host.profile_id || '默认配置' }}</option></select></label>
  <p v-if="error" role="alert">{{ error }}</p>
  <IpCheckView v-if="selected" :key="selected" class="central-check" :bridge="bridge" />
  <p v-else>请先在中心添加设备并分配配置。</p>
</template>
<style scoped>
label{display:flex;align-items:center;gap:12px;margin:20px 0;color:var(--ink-secondary);font-size:13px;flex-wrap:wrap}
select{max-width:100%;padding:10px 14px;border:1px solid var(--paper-border);border-radius:10px;background:var(--paper-surface);color:var(--ink-primary)}
.central-check{--ink:var(--ink-primary);--secondary:var(--ink-secondary);--surface:var(--paper-surface);--border:var(--paper-border);--error:var(--bad);--error-bg:var(--bad-bg)}
</style>
