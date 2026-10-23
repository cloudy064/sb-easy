<template>
  <section class="card access-panel">
    <h3>{{ text('设备组与授权', 'Device groups and access') }}</h3>
    <p class="text-muted">{{ text('管理员拥有全部权限。查看者只能查看授权设备；操作员可重启设备、切换出口和关闭连接。新账户在授权前无法访问设备。', 'Administrators have full access. Viewers can inspect assigned devices. Operators can restart devices, switch proxies and close connections. New accounts have no device access until assigned.') }}</p>
    <p v-if="error" class="error" role="alert">{{ error }}</p><p v-if="message" role="status">{{ message }}</p>
    <div class="columns">
      <form @submit.prevent="saveGroup">
        <h4>{{ text('编辑设备组', 'Edit device group') }}</h4>
        <label>{{ text('设备组', 'Device group') }}<select v-model="groupId" @change="selectGroup"><option value="">{{ text('新建组', 'New group') }}</option><option v-for="group in groups" :key="group.id" :value="group.id">{{ group.name }}</option></select></label>
        <label>{{ text('名称', 'Name') }}<input v-model="groupName" required maxlength="128" /></label>
        <div class="checks"><label v-for="host in hosts" :key="host.id"><input v-model="groupHosts" type="checkbox" :value="host.id" />{{ host.name }}</label></div>
        <div class="actions"><button class="btn-primary" :disabled="busy">{{ text('保存设备组', 'Save group') }}</button><button v-if="groupId" type="button" class="btn-danger" :disabled="busy" @click="removeGroup">{{ text('删除组', 'Delete group') }}</button></div>
      </form>
      <form @submit.prevent="savePolicy">
        <h4>{{ text('账户权限', 'Account permissions') }}</h4>
        <label>{{ text('账户', 'Account') }}<select v-model="userId" @change="loadUser"><option value="" disabled>{{ text('选择账户', 'Select account') }}</option><option v-for="user in users" :key="user.id" :value="user.id">{{ user.username }} · {{ user.role }}</option></select></label>
        <template v-if="userId">
          <label>{{ text('角色', 'Role') }}<select v-model="role"><option>admin</option><option>operator</option><option>viewer</option></select></label>
          <button type="button" class="btn-secondary" :disabled="busy || role === selectedUser?.role" @click="changeRole">{{ text('更新角色并撤销该账户会话', 'Update role and revoke its sessions') }}</button>
          <template v-if="selectedUser?.role !== 'admin'">
            <label>{{ text('访问范围', 'Access scope') }}<select v-model="scope"><option value="groups">{{ text('指定设备组', 'Selected device groups') }}</option><option value="all">{{ text('全部设备（含将来新增）', 'All devices, including future devices') }}</option></select></label>
            <div v-if="scope === 'groups'" class="grants"><label v-for="group in groups" :key="group.id">{{ group.name }}<select v-model="grants[group.id]"><option value="">{{ text('无访问权限', 'No access') }}</option><option value="view">{{ text('查看', 'View') }}</option><option v-if="selectedUser?.role === 'operator'" value="operate">{{ text('查看和操作', 'View and operate') }}</option></select></label></div>
            <button class="btn-primary" :disabled="busy">{{ text('保存授权', 'Save permissions') }}</button>
          </template>
          <button type="button" class="btn-danger" :disabled="busy" @click="revokeUserSessions">{{ text('撤销该账户的所有会话', 'Revoke all sessions for this account') }}</button>
        </template>
      </form>
    </div>
    <hr />
    <h3>{{ text('组织登录（OIDC）', 'Organization sign-in (OIDC)') }}</h3>
    <p class="text-muted">{{ text('仅预先绑定的主体可登录本地账户。配置身份提供商的回调地址为：', 'Only identities linked to a local account may sign in. Register this callback URL with your provider:') }} <code>{{ redirectSuggestion }}</code></p>
    <div class="columns">
      <form @submit.prevent="saveOidc">
        <label class="inline"><input v-model="oidc.enabled" type="checkbox" />{{ text('启用组织登录', 'Enable organization sign-in') }}</label>
        <label>Issuer<input v-model="oidc.issuer" type="url" :required="oidc.enabled" placeholder="https://id.example.com/realms/team" /></label>
        <label>Client ID<input v-model="oidc.client_id" :required="oidc.enabled" /></label>
        <label>{{ text('回调地址', 'Callback URL') }}<input v-model="oidc.redirect_uri" type="url" :required="oidc.enabled" /></label>
        <label>Client secret<input v-model="oidcSecret" type="password" autocomplete="off" :placeholder="oidc.has_client_secret ? text('已设置；留空保持', 'Configured; leave blank to keep') : text('公共客户端可不填', 'Optional for public clients')" /></label>
        <label class="inline"><input v-model="clearSecret" type="checkbox" />{{ text('清除已存储的客户端密钥', 'Clear stored client secret') }}</label>
        <button class="btn-primary" :disabled="busy">{{ text('保存身份提供商', 'Save identity provider') }}</button>
      </form>
      <div>
        <h4>{{ text('敏感操作验证', 'Confirm sensitive changes') }}</h4>
        <label>{{ text('你的当前密码', 'Your current password') }}<input v-model="proofPassword" type="password" autocomplete="current-password" /></label>
        <label>{{ text('你的验证码（已启用双重验证时）', 'Your code (when two-step verification is enabled)') }}<input v-model="proofCode" autocomplete="one-time-code" /></label>
        <p class="text-sm text-muted">{{ text('保存提供商或账户绑定时需要验证。每次操作后请填写新的验证码。', 'Provider and identity-link changes require verification. Use a new code for each operation.') }}</p>
        <template v-if="userId">
          <h4>{{ text('账户绑定', 'Linked identities') }} · {{ selectedUser?.username }}</h4>
          <p v-for="link in links" :key="link.issuer + ':' + link.subject" class="identity">{{ link.issuer }} / {{ link.subject }} <button class="btn-danger btn-sm" :disabled="busy" @click="unlink(link)">{{ text('解除', 'Unlink') }}</button></p>
          <form @submit.prevent="linkIdentity"><label>Issuer<input v-model="linkIssuer" type="url" required /></label><label>Subject (sub)<input v-model="linkSubject" required /></label><button class="btn-secondary" :disabled="busy">{{ text('绑定此身份', 'Link this identity') }}</button></form>
        </template>
      </div>
    </div>
  </section>
</template>
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import client from '../api/client'
import { useI18n } from '../composables/i18n'
import { useAuthStore } from '../stores/auth'
interface User { id: string; username: string; role: string }
interface Group { id: string; name: string; host_ids: string[] }
interface Link { issuer: string; subject: string }
const props = defineProps<{ users: User[] }>(), emit = defineEmits<{ changed: [] }>()
const { locale } = useI18n(), auth = useAuthStore()
const text = (zh: string, en: string) => locale.value === 'zh' ? zh : en
const busy = ref(false), error = ref(''), message = ref('')
const groups = ref<Group[]>([]), hosts = ref<{ id: string; name: string }[]>([])
const groupId = ref(''), groupName = ref(''), groupHosts = ref<string[]>([])
const userId = ref(''), role = ref('viewer'), scope = ref('groups'), grants = ref<Record<string, string>>({})
const selectedUser = computed(() => props.users.find(u => u.id === userId.value))
const redirectSuggestion = window.location.origin + '/login'
const oidc = ref({ enabled: false, issuer: '', client_id: '', redirect_uri: redirectSuggestion, has_client_secret: false })
const oidcSecret = ref(''), clearSecret = ref(false), proofPassword = ref(''), proofCode = ref('')
const links = ref<Link[]>([]), linkIssuer = ref(''), linkSubject = ref('')
async function run(action: () => Promise<void>) {
  if (busy.value) return
  busy.value = true; error.value = ''; message.value = ''
  try { await action(); message.value = text('已保存', 'Saved') }
  catch (e: any) { error.value = e.response?.data?.error || e.message || text('操作失败', 'Operation failed') }
  finally { busy.value = false }
}
async function load() {
  const [groupData, hostData, configData] = await Promise.all([client.get('/device-groups'), client.get('/hosts'), client.get('/auth/oidc/config')])
  groups.value = groupData.data; hosts.value = hostData.data
  oidc.value = { ...oidc.value, ...configData.data }
  linkIssuer.value = oidc.value.issuer
}
function selectGroup() { const group = groups.value.find(g => g.id === groupId.value); groupName.value = group?.name || ''; groupHosts.value = [...(group?.host_ids || [])] }
function saveGroup() { return run(async () => {
  const id = groupId.value || crypto.randomUUID()
  const { data } = await client.put('/device-groups', { id, name: groupName.value, host_ids: groupHosts.value })
  groups.value = data; groupId.value = id
}) }
function removeGroup() { return run(async () => { const { data } = await client.delete(`/device-groups/${groupId.value}`); groups.value = data; groupId.value = ''; selectGroup(); if (userId.value) await loadUserData() }) }
async function loadUserData() {
  if (!userId.value) return
  const [policy, identities] = await Promise.all([client.get(`/users/${userId.value}/scope`), client.get(`/users/${userId.value}/oidc`)])
  scope.value = policy.data.scope; grants.value = Object.fromEntries(policy.data.grants.map((g: { group_id: string; permission: string }) => [g.group_id, g.permission])); links.value = identities.data
  role.value = selectedUser.value?.role || 'viewer'
}
function loadUser() { return run(loadUserData) }
function savePolicy() { return run(async () => {
  const chosen = scope.value === 'groups' ? Object.entries(grants.value).filter(([, permission]) => permission).map(([group_id, permission]) => ({ group_id, permission })) : []
  await client.put(`/users/${userId.value}/scope`, { scope: scope.value, grants: chosen })
}) }
function changeRole() { return run(async () => { await client.put(`/users/${userId.value}/role`, { role: role.value }); if (selectedUser.value?.username === auth.username) { auth.clear(); window.location.assign('/login') } else emit('changed') }) }
function revokeUserSessions() { return run(async () => { await client.delete(`/users/${userId.value}/sessions`); if (selectedUser.value?.username === auth.username) { auth.clear(); window.location.assign('/login') } }) }
const proof = () => ({ password: proofPassword.value, code: proofCode.value })
function clearProof() { proofPassword.value = ''; proofCode.value = '' }
function saveOidc() { return run(async () => {
  const config: Record<string, unknown> = { enabled: oidc.value.enabled, issuer: oidc.value.issuer, client_id: oidc.value.client_id, redirect_uri: oidc.value.redirect_uri }
  if (clearSecret.value || oidcSecret.value) config.client_secret = clearSecret.value ? '' : oidcSecret.value
  const { data } = await client.put('/auth/oidc/config', { ...proof(), config })
  oidc.value = { ...oidc.value, ...data }; oidcSecret.value = ''; clearSecret.value = false; clearProof()
}) }
function linkIdentity() { return run(async () => { const { data } = await client.put(`/users/${userId.value}/oidc`, { ...proof(), issuer: linkIssuer.value, subject: linkSubject.value }); links.value = data; linkSubject.value = ''; clearProof() }) }
function unlink(link: Link) { return run(async () => { const { data } = await client.delete(`/users/${userId.value}/oidc`, { data: { ...proof(), ...link } }); links.value = data; clearProof() }) }
onMounted(() => run(async () => { await load(); message.value = '' }))
</script>
<style scoped>
.access-panel { margin-bottom: 1.5rem; }
h3, h4 { margin-bottom: .8rem; }
.columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 2rem; margin-top: 1.5rem; }
label { display: grid; gap: .4rem; margin: 1rem 0; font-size: .9rem; }
.inline, .checks label { display: flex; align-items: center; gap: .5rem; }
input[type=checkbox] { width: auto; }
.checks, .grants { max-height: 260px; overflow-y: auto; }
.actions { display: flex; gap: .7rem; flex-wrap: wrap; }
button { margin: .3rem .3rem .3rem 0; }
hr { border: 0; border-top: 1px solid var(--paper-border); margin: 2rem 0; }
.identity { overflow-wrap: anywhere; }
.error { color: var(--bad); }
@media (max-width: 780px) { .columns { grid-template-columns: 1fr; } }
</style>
