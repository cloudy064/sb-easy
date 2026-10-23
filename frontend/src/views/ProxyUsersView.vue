<template>
  <div>
    <div class="page-header flex-between">
      <div><h2>{{ tr('代理用户', 'Proxy users') }}</h2><p class="text-sm text-muted">{{ tr('SS2022 用户额度、到期、独立设备凭证与节点授权。', 'SS2022 quotas, expiry, device credentials and node access.') }}</p></div>
      <button class="btn-primary" @click="editUser()">{{ tr('添加代理用户', 'Add proxy user') }}</button>
    </div>
    <p v-if="error" class="error-message" role="alert">{{ error }}</p>
    <div class="card mb-6">
      <div class="flex-between"><h3>{{ tr('受管理的入站节点', 'Managed ingress nodes') }}</h3><button class="btn-secondary" @click="editNode()">{{ tr('配置节点', 'Configure node') }}</button></div>
      <p class="text-sm text-muted">{{ tr('节点须运行支持代理用户租约的版本。保存并启用后开放指定监听端口；还需允许主机防火墙上的 TCP/UDP。', 'Nodes need a runtime with proxy lease support. Enabling a node opens its configured listener; allow its TCP/UDP port in the host firewall.') }}</p>
      <div v-if="!nodes.length" class="empty">{{ tr('先配置至少一个节点，再分配用户。', 'Configure a node before assigning users.') }}</div>
      <div v-for="node in nodes" :key="node.host_id" class="item-row">
        <span><strong>{{ hostName(node.host_id) }}</strong><br><span class="text-sm text-muted">{{ node.server }}:{{ node.listen_port }} · {{ node.enabled ? tr('启用', 'Enabled') : tr('停用', 'Disabled') }} · {{ node.runtime_supported ? tr('运行时已确认支持', 'Runtime support confirmed') : tr('等待支持此功能的运行时上报', 'Waiting for a supported runtime report') }}</span></span>
        <button class="btn-ghost btn-sm" @click="editNode(node)">{{ tr('编辑', 'Edit') }}</button>
      </div>
    </div>
    <div class="card mb-6">
      <div class="flex-between"><h3>{{ tr('用户与额度', 'Users and quotas') }}</h3><button class="btn-ghost btn-sm" :disabled="busy" @click="perform(load)">{{ tr('刷新', 'Refresh') }}</button></div>
      <p class="text-sm text-muted">{{ tr('实测用量来自节点报告。已分配额度包含尚未使用或节点重启后保守扣留的部分；多节点总授权不会超过配额。撤销最迟在 60 秒租约到期时生效。', 'Reported usage comes from nodes. Allocated quota includes unused grants and quota retained after a restart. Total node grants stay within the quota. Revocation takes effect within the 60 second lease lifetime.') }}</p>
      <p v-if="!users.length" class="empty">{{ tr('暂无代理用户。', 'No proxy users yet.') }}</p>
      <article v-for="user in users" :key="user.id" class="user-row">
        <div class="flex-between gap-2"><div><strong>{{ user.name }}</strong> <span class="badge" :class="user.enabled ? 'badge-blue' : 'badge-gray'">{{ user.enabled ? tr('启用', 'Enabled') : tr('停用', 'Disabled') }}</span></div><div class="actions"><button class="btn-ghost btn-sm" @click="editUser(user)">{{ tr('编辑', 'Edit') }}</button><button class="btn-danger btn-sm" :disabled="busy" @click="removeUser(user)">{{ tr('删除', 'Delete') }}</button></div></div>
        <div class="stats">
          <span>{{ tr('实测', 'Reported') }}: <strong>{{ bytes(user.reported_bytes) }}</strong></span>
          <span>{{ tr('已分配', 'Allocated') }}: <strong>{{ bytes(user.allocated_bytes) }} / {{ user.quota_bytes ? bytes(user.quota_bytes) : tr('不限量', 'Unlimited') }}</strong></span>
          <span>{{ tr('到期', 'Expires') }}: {{ date(user.expires_at) }}</span>
          <span>{{ tr('设备', 'Devices') }}: {{ user.devices.filter(activeDevice).length }} / {{ user.max_devices }}</span>
        </div>
        <p v-if="leaseWait(user) > 0" class="text-sm">{{ tr('中心正在等待旧授权失效，还需约 ' + leaseWait(user) + ' 秒；节点收到新租约后恢复。', 'This controller is waiting for prior authorization to expire: about ' + leaseWait(user) + ' seconds remain. Nodes resume after receiving a new lease.') }}</p>
        <p v-else-if="user.not_before > now" class="text-sm">{{ tr('新额度周期等待旧租约到期：', 'New quota period starts after old leases expire: ') }}{{ date(user.not_before) }}</p>
        <p class="text-sm text-muted">{{ tr('节点：', 'Nodes: ') }}{{ user.host_ids.map(hostName).join(', ') || '—' }}</p>
        <div class="actions"><button class="btn-secondary btn-sm" :disabled="busy" @click="rotateClaim(user)">{{ tr('生成领取链接', 'Issue claim link') }}</button><button class="btn-secondary btn-sm" :disabled="busy" @click="issueDevice(user)">{{ tr('创建设备订阅', 'Create device subscription') }}</button><button class="btn-ghost btn-sm" :disabled="busy" @click="resetQuota(user)">{{ tr('重置额度周期', 'Reset quota period') }}</button></div>
        <div v-for="device in user.devices.filter(d => d.enabled)" :key="device.id" class="device-row"><span>{{ device.name }} <small class="text-muted">{{ tr('到期', 'Expires') }}: {{ date(device.expires_at) }}{{ activeDevice(device) ? '' : tr('（已到期）', ' (expired)') }}</small></span><button class="btn-danger btn-sm" :disabled="busy" @click="revoke(user, device)">{{ tr('撤销', 'Revoke') }}</button></div>
      </article>
    </div>
    <div v-if="secret" class="card mb-6" role="status"><h3>{{ secretLabel }}</h3><p class="text-sm text-muted">{{ tr('此凭证仅在本次显示。请复制并私下交给使用者。', 'Shown only now. Copy this credential and share it privately with its owner.') }}</p><textarea readonly :value="secret" rows="3" aria-label="Credential URL"/><div class="actions"><button class="btn-primary" @click="copySecret">{{ tr('复制', 'Copy') }}</button><button class="btn-secondary" @click="secret = ''">{{ tr('关闭', 'Dismiss') }}</button><span v-if="copied">{{ tr('已复制', 'Copied') }}</span></div></div>
    <div v-if="deviceForm" class="modal-overlay" @click.self="!busy && (deviceForm = null)"><div class="modal"><h3>{{ tr('创建设备订阅', 'Create device subscription') }} — {{ deviceForm.user.name }}</h3><form @submit.prevent="saveDevice"><div class="form-group"><label for="device-name">{{ tr('设备名称', 'Device name') }}</label><input id="device-name" v-model="deviceForm.name" required maxlength="128"></div><div class="form-group"><label for="device-expiry">{{ tr('设备到期时间（留空继承用户期限）', 'Device expiry (empty inherits the user expiry)') }}</label><input id="device-expiry" v-model="deviceForm.expiry" type="datetime-local"></div><p v-if="error" class="error-message">{{ error }}</p><div class="modal-actions"><button type="button" class="btn-secondary" :disabled="busy" @click="deviceForm = null">{{ tr('取消', 'Cancel') }}</button><button class="btn-primary" :disabled="busy">{{ tr('创建', 'Create') }}</button></div></form></div></div>
    <div v-if="userForm" class="modal-overlay" @click.self="!busy && (userForm = null)"><div class="modal"><h3>{{ userForm.id ? tr('编辑代理用户', 'Edit proxy user') : tr('添加代理用户', 'Add proxy user') }}</h3>
      <form @submit.prevent="saveUser"><div class="form-group"><label>{{ tr('名称', 'Name') }}</label><input v-model="userForm.name" maxlength="128" required></div><div class="form-group"><label>{{ tr('配额（字节，0 不限量）', 'Quota (bytes, 0 means unlimited)') }}</label><input v-model.number="userForm.quota_bytes" type="number" min="0" max="9007199254740991" step="1" required></div><div class="form-group"><label>{{ tr('到期时间（留空不限期）', 'Expiry (empty means no expiry)') }}</label><input v-model="userForm.expiry" type="datetime-local"></div><div class="form-group"><label>{{ tr('最大设备凭证数', 'Maximum device credentials') }}</label><input v-model.number="userForm.max_devices" type="number" min="1" max="32" step="1" required></div><label class="check"><input v-model="userForm.enabled" type="checkbox">{{ tr('启用', 'Enabled') }}</label>
        <fieldset><legend>{{ tr('分配节点', 'Assigned nodes') }}</legend><label v-for="node in nodes" :key="node.host_id" class="check"><input v-model="userForm.host_ids" type="checkbox" :value="node.host_id">{{ hostName(node.host_id) }} · {{ node.server }}</label></fieldset><p class="text-sm text-muted">{{ tr('设备限制约束独立凭证数量；同一凭证被复制到其它物理设备无法据此识别。', 'The limit counts independent credentials. Copies of the same credential cannot identify physical devices.') }}</p><p v-if="error" class="error-message">{{ error }}</p><div class="modal-actions"><button type="button" class="btn-secondary" :disabled="busy" @click="userForm = null">{{ tr('取消', 'Cancel') }}</button><button class="btn-primary" :disabled="busy">{{ tr('保存', 'Save') }}</button></div>
      </form></div></div>
    <div v-if="nodeForm" class="modal-overlay" @click.self="!busy && (nodeForm = null)"><div class="modal"><h3>{{ tr('配置受管理入站', 'Configure managed ingress') }}</h3><form @submit.prevent="saveNode"><div class="form-group"><label>{{ tr('主机', 'Host') }}</label><select v-model="nodeForm.host_id" required><option value="" disabled>{{ tr('选择主机', 'Select host') }}</option><option v-for="host in hosts.filter(h => h.enabled)" :key="host.id" :value="host.id">{{ host.name }}</option></select></div><div class="form-group"><label>{{ tr('公开域名或 IP', 'Public hostname or IP') }}</label><input v-model="nodeForm.server" required placeholder="proxy.example.com"></div><div class="form-group"><label>{{ tr('监听 IP', 'Listen IP') }}</label><input v-model="nodeForm.listen" required placeholder="0.0.0.0"></div><div class="form-group"><label>{{ tr('监听端口', 'Listen port') }}</label><input v-model.number="nodeForm.listen_port" type="number" min="1" max="65535" step="1" required></div><label class="check"><input v-model="nodeForm.enabled" type="checkbox">{{ tr('启用并开放入站', 'Enable ingress listener') }}</label><p v-if="error" class="error-message">{{ error }}</p><div class="modal-actions"><button type="button" class="btn-secondary" :disabled="busy" @click="nodeForm = null">{{ tr('取消', 'Cancel') }}</button><button class="btn-primary" :disabled="busy">{{ tr('保存', 'Save') }}</button></div></form></div></div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import client from '../api/client'
import { useI18n } from '../composables/i18n'
const { locale } = useI18n()
const tr = (zh: string, en: string) => locale.value === 'zh' ? zh : en
interface Device { id: string; name: string; enabled: boolean; created_at: number; expires_at: number }
interface User { id: string; name: string; enabled: boolean; quota_bytes: number; expires_at: number; max_devices: number; host_ids: string[]; allocated_bytes: number; reported_bytes: number; not_before: number; lease_wait_seconds: number; devices: Device[] }
interface Node { host_id: string; enabled: boolean; server: string; listen: string; listen_port: number; runtime_supported?: boolean; runtime_seen_at?: number }
interface Host { id: string; name: string; enabled: boolean }
const users = ref<User[]>([]), nodes = ref<Node[]>([]), hosts = ref<Host[]>([])
const busy = ref(false), error = ref(''), secret = ref(''), secretLabel = ref(''), copied = ref(false)
const userForm = ref<{ id?: string; name: string; enabled: boolean; quota_bytes: number; expiry: string; max_devices: number; host_ids: string[] } | null>(null)
const nodeForm = ref<Node | null>(null)
const deviceForm = ref<{ user: User; name: string; expiry: string } | null>(null)
const now = ref(Math.floor(Date.now() / 1000))
const monotonicNow = ref(performance.now())
let loadedAt = performance.now()
const leaseWait = (user: User) => Math.max(0, (user.lease_wait_seconds || 0) - Math.floor((monotonicNow.value - loadedAt) / 1000))
let clock: ReturnType<typeof setInterval>
const activeDevice = (device: Device) => device.enabled && (!device.expires_at || device.expires_at > now.value)
const hostName = (id: string) => hosts.value.find(h => h.id === id)?.name || id
const date = (seconds: number) => seconds ? new Date(seconds * 1000).toLocaleString() : tr('不限期', 'No expiry')
function bytes(n: number) { if (n < 1024) return `${n} B`; const power = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 4); return `${(n / 1024 ** power).toFixed(2)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][power]}` }
async function load() { const [u, n, h] = await Promise.all([client.get('/proxy-users'), client.get('/proxy-ingress'), client.get('/hosts')]); users.value = u.data; nodes.value = n.data; hosts.value = h.data; loadedAt = performance.now(); monotonicNow.value = loadedAt }
async function perform(action: () => Promise<void>) { if (busy.value) return; busy.value = true; error.value = ''; try { await action() } catch (e: any) { error.value = e.response?.data?.error || e.message || tr('操作失败', 'Operation failed') } finally { busy.value = false } }
function editUser(user?: User) { error.value = ''; const d = user?.expires_at ? new Date(user.expires_at * 1000) : null; const expiry = d ? new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16) : ''; userForm.value = { id: user?.id, name: user?.name || '', enabled: user?.enabled ?? true, quota_bytes: user?.quota_bytes || 0, expiry, max_devices: user?.max_devices || 3, host_ids: [...(user?.host_ids || [])] } }
function editNode(node?: Node) { error.value = ''; nodeForm.value = node ? { ...node } : { host_id: '', enabled: false, server: '', listen: '0.0.0.0', listen_port: 8388 } }
async function saveUser() { await perform(async () => { const f = userForm.value!; if (!Number.isSafeInteger(f.quota_bytes)) throw new Error(tr('请输入有效整数配额', 'Enter a safe integer quota')); const payload = { name: f.name, enabled: f.enabled, quota_bytes: f.quota_bytes, expires_at: f.expiry ? Math.floor(new Date(f.expiry).getTime() / 1000) : 0, max_devices: f.max_devices, host_ids: f.host_ids }; if (f.id) await client.put(`/proxy-users/${f.id}`, payload); else await client.post('/proxy-users', payload); userForm.value = null; await load() }) }
async function saveNode() { await perform(async () => { const f = nodeForm.value!; await client.put(`/proxy-ingress/${f.host_id}`, { enabled: f.enabled, server: f.server, listen: f.listen, listen_port: f.listen_port }); nodeForm.value = null; await load() }) }
function showSecret(label: string, url: string) { secretLabel.value = label; secret.value = url; copied.value = false }
async function rotateClaim(user: User) { if (!window.confirm(tr('生成新领取链接会使旧领取链接失效；已领取的设备订阅仍有效。继续？', 'A new claim link invalidates the previous claim link. Existing device subscriptions stay valid. Continue?'))) return; await perform(async () => { const { data } = await client.post(`/proxy-users/${user.id}/claim-token`); showSecret(tr('用户领取链接', 'User claim link'), `${window.location.origin}/proxy-access#token=${encodeURIComponent(data.claim_token)}`) }) }
function issueDevice(user: User) { error.value = ''; deviceForm.value = { user, name: '', expiry: '' } }
async function saveDevice() { await perform(async () => { const form = deviceForm.value!; const expires_at = form.expiry ? Math.floor(new Date(form.expiry).getTime() / 1000) : 0; const { data } = await client.post(`/proxy-users/${form.user.id}/devices`, { name: form.name, expires_at }); deviceForm.value = null; showSecret(tr('设备订阅链接', 'Device subscription link'), `${window.location.origin}/api/proxy-self/subscription?token=${encodeURIComponent(data.subscription_token)}`); await load() }) }
async function revoke(user: User, device: Device) { if (!window.confirm(tr(`撤销 ${device.name} 的凭证？最迟 60 秒生效。`, `Revoke ${device.name}? Takes effect within 60 seconds.`))) return; await perform(async () => { await client.delete(`/proxy-users/${user.id}/devices/${device.id}`); await load() }) }
async function resetQuota(user: User) { if (!window.confirm(tr('重置后中心至少等待 60 秒，确认旧授权失效，再发放新周期额度。节点续租或其他中心观察到重置可能稍晚。继续？', 'The controller waits at least 60 seconds after reset before granting a new period. Node renewal or another controller observing the reset may add delay. Continue?'))) return; await perform(async () => { await client.post(`/proxy-users/${user.id}/reset`); await load() }) }
async function removeUser(user: User) { if (!window.confirm(tr(`删除 ${user.name} 并撤销全部设备？`, `Delete ${user.name} and revoke all devices?`))) return; await perform(async () => { await client.delete(`/proxy-users/${user.id}`); await load() }) }
async function copySecret() { await perform(async () => { await navigator.clipboard.writeText(secret.value); copied.value = true }) }
onMounted(() => { clock = setInterval(() => { now.value = Math.floor(Date.now() / 1000); monotonicNow.value = performance.now() }, 1000); void perform(load) })
onUnmounted(() => clearInterval(clock))
</script>

<style scoped>
h3 { margin-bottom: .7rem; } .item-row,.device-row { display:flex; align-items:center; justify-content:space-between; gap:1rem; padding:.8rem 0; border-bottom:1px solid var(--paper-border); } .user-row { padding:1rem 0; border-bottom:1px solid var(--paper-border); } .user-row:last-child { border:0; } .stats { display:flex; flex-wrap:wrap; gap:.6rem 1.4rem; margin:.8rem 0; font-size:.85rem; } .actions { display:flex; align-items:center; flex-wrap:wrap; gap:.5rem; margin:.6rem 0; } .device-row { margin-left:1rem; font-size:.85rem; } .check { display:flex; gap:.5rem; align-items:center; margin:.6rem 0; } .check input { width:auto; } fieldset { margin-top:1rem; border:1px solid var(--paper-border); border-radius:6px; padding:.8rem; } .error-message { color:var(--bad); margin:.6rem 0; } .empty { padding:1rem 0; color:var(--ink-muted); } textarea { width:100%; font-family:monospace; } .modal { max-height:90vh; overflow:auto; }
</style>
