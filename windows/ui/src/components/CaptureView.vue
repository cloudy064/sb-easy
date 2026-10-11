<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import type { NativeBridge } from '../lib/bridge'
import type { CaptureConfig, CaptureSnapshot } from '../lib/protocol'
import { bytes } from '../lib/dashboard'
const props = defineProps<{ bridge: NativeBridge; server: string }>()
const state = ref<CaptureSnapshot | null>(null), form = ref<CaptureConfig | null>(null)
const domains = ref(''), hosts = ref(''), appSearch = ref(''), customApp = ref('')
const busy = ref(false), error = ref(''), notice = ref(''), confirm = ref<{ action: 'upload' | 'delete'; digest: string } | null>(null)
const page = ref(0)
let disposed = false, timer: ReturnType<typeof setTimeout> | undefined
const apps = computed(() => [...new Set([...(state.value?.apps ?? []), ...(form.value?.apps ?? [])])].sort().filter(app => app.toLowerCase().includes(appSearch.value.toLowerCase())))
const files = computed(() => [...(state.value?.files ?? [])].sort((a,b) => b.created_at-a.created_at))
const visibleFiles = computed(() => files.value.slice(page.value*20,page.value*20+20))
function adopt(value: CaptureConfig) { form.value = structuredClone(value); domains.value = value.domains.join('\n'); hosts.value = value.hosts.join('\n') }
function normalize(text: string): string[] {
  return [...new Set(text.split(/[\s,，]+/).filter(Boolean).map(value => {
    if (/[/?#@]/.test(value)) throw new Error('域名或 IP 不能包含路径、参数或用户名')
    const url = new URL(`https://${value.includes(':') && !value.startsWith('[') ? `[${value}]` : value}/`)
    if (url.port) throw new Error('请填写域名或 IP，不要包含端口')
    return url.hostname.replace(/^\[|\]$/g,'').replace(/\.$/,'').toLowerCase()
  }))]
}
function config(): CaptureConfig {
  if (!form.value) throw new Error('尚未读取采集配置')
  return { ...form.value, apps:[...new Set(form.value.apps)], domains: normalize(domains.value), hosts: normalize(hosts.value), bpf: form.value.bpf.trim() }
}
function addApp() { const app=customApp.value.trim(); if (app && form.value && !form.value.apps.includes(app)) form.value.apps.push(app); customApp.value='' }
async function refresh() {
  if (busy.value) return
  try { const result=await props.bridge.request('capture.snapshot'); if (!disposed) { state.value=result; if (!form.value) adopt(result.config); error.value='' } }
  catch(e) { if (!disposed) error.value=e instanceof Error?e.message:'采集状态读取失败' }
}
async function action(kind: 'save' | 'validate' | 'stop' | 'rotate' | 'upload' | 'delete', digest='') {
  if (busy.value) return
  busy.value=true; error.value='';notice.value=''
  try {
    if (kind==='validate') { await props.bridge.request('capture.validate',{config:config()}); notice.value='BPF 及采集配置校验通过' }
    else {
      const result=kind==='save'||kind==='stop' ? await props.bridge.request('capture.configure',{config:kind==='stop' ? {...state.value!.config, enabled:false} : config()}) :
        kind==='rotate' ? await props.bridge.request('capture.rotate') : kind==='upload' ? await props.bridge.request('capture.upload',{digest}) : await props.bridge.request('capture.delete',{digest})
      if (disposed) return
      state.value=result
      if (kind==='save'||kind==='stop') { adopt(result.config); notice.value=result.config.enabled ? result.running ? '采集已启动' : '设置已保存；启用 TUN 连接后采集，运行错误请查看下方提示' : '采集已关闭' }
      if (kind==='upload') notice.value='上传任务已开始，完成后显示服务器确认结果'
      confirm.value=null
    }
  } catch(e) {error.value=e instanceof Error?e.message:'操作失败'}
  finally {busy.value=false}
}
async function download(digest: string) {
  busy.value=true;error.value=''
  try {
    const chunks: Uint8Array<ArrayBuffer>[]=[];let offset=0,total=0
    do {
      const chunk=await props.bridge.request('capture.read',{digest,offset})
      if(chunk.offset!==offset||chunk.next<=offset||(total&&chunk.total!==total))throw new Error('采集文件分段响应异常')
      const binary=atob(chunk.data), array=new Uint8Array(binary.length)
      for(let i=0;i<binary.length;i++)array[i]=binary.charCodeAt(i)
      if(array.length!==chunk.next-offset)throw new Error('采集文件长度不匹配')
      chunks.push(array);offset=chunk.next;total=chunk.total
    }while(offset<total)
    const blob=new Blob(chunks,{type:'application/vnd.tcpdump.pcap'})
    const hash=[...new Uint8Array(await crypto.subtle.digest('SHA-256',await blob.arrayBuffer()))].map(v=>v.toString(16).padStart(2,'0')).join('')
    if(hash!==digest)throw new Error('PCAP 校验失败，未导出')
    const url=URL.createObjectURL(blob), link=document.createElement('a');link.href=url;link.download=`sb-easy-${digest.slice(0,16)}.pcap`;link.click();setTimeout(()=>URL.revokeObjectURL(url),60000)
    notice.value='已提交 PCAP 下载，请在下载提示中选择保存位置'
  }catch(e){error.value=e instanceof Error?e.message:'导出失败'}finally{busy.value=false}
}
async function poll(){if(!disposed&&document.visibilityState==='visible')await refresh();if(!disposed)timer=setTimeout(()=>void poll(),3000)}
onMounted(()=>void poll());onBeforeUnmount(()=>{disposed=true;clearTimeout(timer)})
</script>
<template>
  <p v-if="error" class="error-notice" role="alert">{{ error }}</p><p v-if="notice" class="action-notice" role="status">{{ notice }}</p>
  <section v-if="state" class="panel capture-summary"><div><span class="status-tag">{{ state.running ? '正在采集' : state.config.enabled ? '等待 TUN / 检查状态' : '采集已关闭' }}</span><h2>{{ state.packets.toLocaleString() }} 个数据包</h2><p>本地 {{ bytes(state.stored_bytes) }} / {{ state.config.quota_mb }} MB · {{ state.files.length }} 个文件 · {{ state.dropped }} 个包未保存</p></div><div class="stat-actions"><button class="secondary-button" :disabled="busy" @click="action('rotate')">封口当前文件</button><button class="secondary-button" :disabled="busy || !state.config.enabled" @click="action('stop')">停止采集</button></div></section>
  <p v-if="state?.error" class="error-notice" role="alert">{{ state.error }}</p>
  <form v-if="form" @submit.prevent="action('save')" class="capture-form"><fieldset :disabled="busy">
    <section class="panel"><div class="section-heading"><h2>采集范围</h2><label class="capture-check"><input type="checkbox" v-model="form.enabled" />启用采集</label></div><p class="section-description">仅采集经过 sb-easy TUN 的 TCP/UDP 原始 IP 包；HTTPS / QUIC 内容仍保持加密。应用、域名、host 条件之间为“或”，再与 BPF 条件取“且”。</p>
      <label class="input-label">应用（Windows 进程名）</label><input v-model="appSearch" class="stat-search" placeholder="搜索正在运行或已选择的应用" aria-label="搜索采集应用"/>
      <div class="capture-apps"><label v-for="app in apps" :key="app" class="capture-check"><input type="checkbox" :value="app" v-model="form.apps"/><span>{{ app }}</span></label></div>
      <div class="capture-add"><input v-model="customApp" placeholder="也可填写尚未运行的程序，如 Codex.exe" maxlength="96" aria-label="手动添加进程名"/><button type="button" class="secondary-button" @click="addApp">添加应用</button></div>
      <p class="input-hint">已选择：{{ form.apps.join('、') || '无' }}。相同文件名的程序合并筛选。</p>
      <div class="capture-columns"><label>域名（包含子域名）<textarea v-model="domains" rows="3" placeholder="example.com" /></label><label>精确 host / IP<textarea v-model="hosts" rows="3" placeholder="api.example.com&#10;10.59.32.2"/></label></div>
      <label class="input-label" for="capture-bpf">BPF 表达式（可选）</label><textarea id="capture-bpf" v-model="form.bpf" rows="2" maxlength="4096" placeholder="tcp port 443 or udp port 53"/><p class="input-hint">标准 libpcap 语法，支持单独使用 BPF。IP 匹配 TUN 内原始地址，可能是 FakeIP；网站名请填入域名栏。</p>
    </section>
    <section class="panel"><div class="section-heading"><h2>文件与上传</h2></div><div class="capture-columns capture-numbers"><label>单文件上限（KB）<input type="number" v-model.number="form.file_kb" min="128" max="768"/></label><label>本地容量（MB）<input type="number" v-model.number="form.quota_mb" min="8" max="256"/></label><label>文件轮转（秒）<input type="number" v-model.number="form.rotate_seconds" min="10" max="600"/></label><label>上传间隔（秒）<input type="number" v-model.number="form.upload_seconds" min="30" max="3600"/></label></div>
      <div class="capture-options"><label class="capture-check"><input type="checkbox" v-model="form.auto_upload"/>自动上传到当前中心</label><label class="capture-check"><input type="checkbox" v-model="form.wifi_only"/>仅在 Wi-Fi 已连接时上传</label><label class="capture-check"><input type="checkbox" v-model="form.delete_after_upload"/>服务器确认后删除本地文件</label></div><p class="input-hint">当前中心：{{ server || '尚未注册' }}。采集和自动上传默认关闭；达到容量后暂停写入，已有文件不会自动被覆盖。上传遵循系统路由，Wi-Fi 选项仅控制是否允许开始上传。</p>
      <div class="stat-actions"><button type="submit" class="primary-button">{{ busy ? '处理中…' : '保存并应用' }}</button><button type="button" class="secondary-button" @click="action('validate')">检查 BPF / 配置</button></div>
    </section>
  </fieldset></form>
  <section v-if="state" class="panel capture-files"><div class="section-heading"><h2>PCAP 文件</h2><button class="text-button" :disabled="busy" @click="refresh">刷新</button></div><p v-if="state.upload_status" class="section-description">{{ state.uploading ? '上传中 · ' : '' }}{{ state.upload_status }}</p>
    <div v-if="confirm" class="capture-confirm"><strong>{{ confirm.action==='upload' ? '上传此原始流量文件到当前中心？' : '删除此本地采集文件？' }}</strong><p>{{ confirm.action==='upload' ? `目标：${server}。文件可能包含明文协议数据、域名与 IP。` : '删除后不可恢复；已上传的中心副本不会被删除。' }}</p><button class="primary-button" :disabled="busy" @click="action(confirm.action,confirm.digest)">确认{{ confirm.action==='upload' ? '上传' : '删除' }}</button><button class="secondary-button" @click="confirm=null">取消</button></div>
    <div v-for="file in visibleFiles" :key="file.digest" class="capture-file"><div><strong>{{ new Date(file.created_at).toLocaleString('zh-CN') }}</strong><p>{{ bytes(file.size) }} · {{ file.digest.slice(0,16) }} · {{ file.uploaded ? '已上传' : '待上传' }}</p></div><div class="stat-actions"><button class="secondary-button" :disabled="busy" @click="download(file.digest)">导出</button><button class="secondary-button" :disabled="busy || state.uploading || file.uploaded" @click="confirm={action:'upload',digest:file.digest}">上传</button><button class="text-button" :disabled="busy || state.uploading" @click="confirm={action:'delete',digest:file.digest}">删除</button></div></div>
    <div v-if="!files.length" class="empty-state"><h2>暂无已封口的文件</h2><p>设置筛选条件并启用采集，启动 TUN 后访问目标。可以点击“封口当前文件”提前保存。</p></div><div v-if="files.length>20" class="stat-actions"><button class="secondary-button" :disabled="page===0" @click="page--">上一页</button><span>{{ page+1 }} / {{ Math.ceil(files.length/20) }}</span><button class="secondary-button" :disabled="(page+1)*20>=files.length" @click="page++">下一页</button></div>
  </section><p class="collection-note">应用和域名归属来自内核连接快照，短连接可能无法及时识别；未知包只在内存等待最多 10 秒，匹配前不会落盘。PCAP 可用 Wireshark 打开。采集副本丢弃不会阻断网络转发。</p>
</template>
<style>
.capture-summary{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:20px}.capture-summary h2{margin:16px 0 8px}.capture-summary p{font-size:12px;color:var(--secondary)}.capture-form fieldset{border:0;padding:0;margin:0;display:grid;gap:20px}.capture-form .panel{padding:24px}.capture-form .input-label{margin-top:20px}.capture-check{display:flex;align-items:center;gap:9px;font-size:12px}.capture-check input{width:15px;height:15px;accent-color:var(--accent)}.capture-apps{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;max-height:190px;overflow:auto;margin:18px 0}.capture-apps span{overflow-wrap:anywhere}.capture-add{display:flex;gap:10px}.capture-add input{min-width:0;flex:1}.capture-add input,.capture-numbers input{border:1px solid var(--border);border-radius:8px;padding:10px;color:var(--ink);background:var(--surface);font-size:12px}.capture-columns{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:20px 0}.capture-columns label{font-size:12px;color:var(--secondary)}.capture-columns textarea,.capture-columns input{display:block;width:100%;margin-top:8px}.capture-options{display:flex;flex-wrap:wrap;gap:18px;margin:20px 0}.capture-form .stat-actions{margin-top:20px}.capture-files{margin-top:22px}.capture-file{display:flex;justify-content:space-between;align-items:center;gap:20px;padding:18px 0;border-top:1px solid var(--border)}.capture-file strong{font-size:13px}.capture-file p{font-size:11px;color:var(--secondary)}.capture-confirm{padding:18px;background:var(--accent-bg);border-radius:10px;margin:16px 0}.capture-confirm p{font-size:12px;margin:10px 0}.capture-confirm button{margin-right:10px}@media(max-width:800px){.capture-apps{grid-template-columns:1fr 1fr}.capture-summary,.capture-file{align-items:flex-start;flex-direction:column}.capture-columns{grid-template-columns:1fr}}
</style>
