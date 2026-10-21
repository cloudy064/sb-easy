<template>
  <div class="modal-overlay" @click.self="emit('close')">
    <section class="modal access-modal" role="dialog" aria-modal="true" aria-labelledby="access-title">
      <header class="access-head"><div><h3 id="access-title">代理入口</h3><p class="text-sm text-muted">{{ profile.name }} · 一个端口，按用户名选择出口</p></div><button class="btn-ghost" aria-label="关闭" @click="emit('close')">✕</button></header>
      <label class="access-toggle"><input type="checkbox" v-model="access.enabled" /> 启用共享代理入口</label>
      <template v-if="access.enabled">
        <div class="access-fields"><label>监听地址<input v-model="access.listen" placeholder="127.0.0.1" /></label><label>共享端口<input type="number" min="1" max="65535" v-model.number="access.port" /></label></div>
        <p class="text-xs text-muted">默认仅允许本机连接。需要其他设备使用时，可设为 0.0.0.0。所有用户名共用此端口，原有代理入口不变。</p>
        <div class="access-users">
          <article v-for="(user, i) in access.users" :key="i" class="access-user">
            <div class="access-fields"><label>入口类型<select :value="user.kind" @change="changeKind(user, ($event.target as HTMLSelectElement).value)"><option value="group">跟随规则组</option><option value="node">固定节点</option><option v-if="user.kind === 'legacy'" value="legacy">旧版名称绑定（建议迁移）</option></select></label><label v-if="user.kind === 'node'">固定节点<select :value="user.nodeId" @change="selectNode(user, ($event.target as HTMLSelectElement).value)"><option disabled value="">选择节点</option><option v-if="!nodes.some(n => n.id === user.nodeId) && user.nodeId" :value="user.nodeId">节点已删除 · 连接将被拒绝</option><option v-for="node in nodes" :key="node.id" :value="node.id" :disabled="!node.enabled">{{ node.tag }}{{ node.enabled ? '' : '（停用）' }}</option></select></label><label v-else>规则组<select v-model="user.outbound"><option disabled value="">选择规则组</option><option v-if="user.kind === 'legacy'" :value="user.outbound">{{ user.outbound }}（旧绑定）</option><option v-for="tag in groups" :key="tag" :value="tag">{{ tag }}</option></select></label></div>
            <label>用户名<input v-model="user.username" :readonly="user.kind === 'node'" placeholder="例如 google（node_ 前缀保留给固定入口）" autocomplete="off" /></label>
            <p class="text-xs text-muted">{{ user.kind === 'node' ? '绑定节点 ID，改名不影响；删除、停用或不可达时不会切换其他出口。' : '跟随规则组当前选择的节点。' }}</p>
            <label>访问密钥<div class="access-secret"><input v-model="user.password" :type="revealed === i ? 'text' : 'password'" autocomplete="new-password" /><button class="btn-ghost btn-sm" @click="revealed = revealed === i ? -1 : i">{{ revealed === i ? '隐藏' : '显示' }}</button><button class="btn-ghost btn-sm" @click="regenerate(i)">重新生成</button></div></label>
            <div class="access-row"><span class="text-xs text-muted">此用户名的请求优先使用指定出口</span><div><button class="btn-ghost btn-sm" :disabled="dirty || saving" @click="copy(user)">复制地址</button><button class="btn-danger btn-sm" @click="access.users.splice(i, 1)">删除</button></div></div>
          </article>
        </div>
        <div class="access-row"><button class="btn-secondary btn-sm" @click="addUser">＋ 添加规则组入口</button><button class="btn-secondary btn-sm" @click="addFixed">＋ 添加固定节点入口</button></div>
        <div class="access-fields address-fields"><label>连接地址中的主机<input v-model="host" placeholder="运行 agent 的 IP 或域名" /></label><label>代理协议<select v-model="scheme"><option value="http">HTTP（支持 HTTPS 目标）</option><option value="socks5h">SOCKS5（代理解析域名）</option></select></label></div>
        <p class="text-xs text-muted">填写实际运行 agent 的地址，而非中心管理网页的地址。保存后才能复制；修改密钥后需更新调用方。</p>
        <label v-if="copiedUrl">代理地址<input :value="copiedUrl" readonly @focus="($event.target as HTMLInputElement).select()" /></label>
      </template>
      <p v-else class="text-sm text-muted">关闭后将移除此专用监听端口，不再接受这些用户名的连接。</p>
      <p v-if="error" role="alert" class="access-error">{{ error }}</p><p v-if="notice" role="status" class="text-sm">{{ notice }}</p>
      <footer class="modal-actions"><button class="btn-secondary" :disabled="saving" @click="emit('close')">关闭</button><button class="btn-primary" :disabled="saving || !dirty" @click="save">{{ saving ? '保存中…' : '保存配置' }}</button></footer>
    </section>
  </div>
</template>
<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { ConfigProfile } from '../types'
import { useHostsStore } from '../stores/hosts'
import { readAccess, writeAccess, newAccessKey, proxyUrl, fixedUsername, fixedOutbound, type AccessUser, type AccessNode } from '../lib/proxyAccess'
const props = defineProps<{ profile: ConfigProfile; nodes: AccessNode[]; initialNodeId?: string }>()
const emit = defineEmits<{ close: [] }>()
const store = useHostsStore()
let config = JSON.parse(props.profile.template)
const access = reactive(readAccess(config))
const groups = computed<string[]>(() => props.profile.mode === 'full'
  ? (config.outbounds ?? []).filter((x: any) => ['selector', 'urltest'].includes(x.type)).map((x: any) => x.tag)
  : ['Proxy', 'auto'])
for (const user of access.users) user.kind ??= groups.value.includes(user.outbound) ? 'group' : 'legacy'
const baseline = ref(JSON.stringify(access))
const dirty = computed(() => JSON.stringify(access) !== baseline.value)
const targets = computed<string[]>(() => [...groups.value, ...readAccess(config).users.filter(u => !u.username.startsWith('node_')).map(u => u.outbound)])
const host = ref(''), scheme = ref('http'), copiedUrl = ref(''), error = ref(''), notice = ref(''), saving = ref(false), revealed = ref(-1)
watch([access, host, scheme], () => { copiedUrl.value = ''; notice.value = '' })
function addUser() { try { access.users.push({ kind: 'group', username: '', password: newAccessKey(), outbound: '' }); error.value = '' } catch (e: any) { error.value = e.message } }
function selectNode(user: AccessUser, id: string) { user.nodeId = id; user.username = fixedUsername(id); user.outbound = fixedOutbound(id) }
function changeKind(user: AccessUser, kind: string) { user.kind = kind as AccessUser['kind']; user.username = ''; user.outbound = ''; user.nodeId = '' }
function addFixed() { try { access.users.push({ kind: 'node', nodeId: '', username: '', password: newAccessKey(), outbound: '' }) } catch (e: any) { error.value = e.message } }
if (props.initialNodeId && !access.users.some(u => u.username === fixedUsername(props.initialNodeId!))) {
  access.enabled = true; addFixed()
  const last = access.users[access.users.length - 1]; if (last?.kind === 'node' && !last.nodeId) selectNode(last, props.initialNodeId)
}
function regenerate(i: number) { try { access.users[i]!.password = newAccessKey() } catch (e: any) { error.value = e.message } }
async function copy(user: AccessUser) {
  try { copiedUrl.value = proxyUrl(host.value, access.port, user, scheme.value); await navigator.clipboard.writeText(copiedUrl.value); notice.value = '代理地址已复制' }
  catch (e: any) { if (copiedUrl.value) notice.value = '请在上方选中地址后复制'; else error.value = e.message }
}
async function save() {
  error.value = ''; notice.value = ''
  try {
    const next = writeAccess(config, JSON.parse(JSON.stringify(access)), targets.value, props.nodes)
    saving.value = true
    await store.updateProfile(props.profile.id, props.profile.name, next, props.profile.rule_script, props.profile.rule_script_enabled, props.profile.mode)
    config = next; baseline.value = JSON.stringify(access)
    notice.value = '已保存。使用此配置的 agent 将在下次同步时应用；可在设备页确认状态。'
  } catch (e: any) { error.value = e?.response?.data?.error || e.message || '保存失败' }
  finally { saving.value = false }
}
</script>
<style scoped>
.access-modal{width:min(760px,94vw);max-width:760px;max-height:88vh;overflow:auto;display:flex;flex-direction:column;gap:18px}
.access-head,.access-row{display:flex;align-items:center;justify-content:space-between;gap:12px}.access-head h3{margin-bottom:6px}
.access-toggle{display:flex;align-items:center;gap:10px;font-weight:600}.access-toggle input{width:auto}
.access-fields{display:grid;grid-template-columns:1fr 1.7fr;gap:14px}.access-modal label{display:flex;flex-direction:column;gap:7px;font-size:13px}.access-modal label.access-toggle{flex-direction:row}
.access-users{display:grid;gap:12px}.access-user{padding:18px;border:1px solid var(--paper-border,#e2dfd8);border-radius:12px;display:grid;gap:14px;background:var(--paper-surface,transparent)}
.access-secret{display:flex;gap:6px;align-items:center}.access-secret input{min-width:0;flex:1}.access-row>div{display:flex;gap:8px}.access-error{color:#ef8080;font-size:13px}.address-fields{margin-top:4px}
@media(max-width:600px){.access-fields{grid-template-columns:1fr}.access-row{align-items:flex-start;flex-direction:column}.access-secret{flex-wrap:wrap}}
</style>
