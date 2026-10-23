<template>
  <div class="security-page">
    <div class="page-header"><h2>{{ text('账户安全', 'Account security') }}</h2><p class="text-muted">{{ auth.username }} · {{ auth.role }}</p></div>
    <p v-if="error" class="notice error" role="alert">{{ error }}</p>
    <p v-if="message" class="notice" role="status">{{ message }}</p>
    <section class="card">
      <h3>{{ text('双重验证', 'Two-step verification') }}</h3>
      <p>{{ mfa.enabled ? text('已启用', 'Enabled') : text('未启用', 'Not enabled') }} · {{ text('剩余恢复码', 'Recovery codes remaining') }}: {{ mfa.recovery_codes_remaining }}</p>
      <form v-if="!pending && !recoveryCodes.length" @submit.prevent="changeMfa('setup')">
        <label>{{ text('当前密码', 'Current password') }}<input v-model="password" type="password" autocomplete="current-password" required /></label>
        <label v-if="mfa.enabled">{{ text('验证码或恢复码', 'Authenticator or recovery code') }}<input v-model="code" autocomplete="one-time-code" required /></label>
        <div class="actions"><button class="btn-primary" :disabled="busy">{{ mfa.enabled ? text('更换认证器', 'Replace authenticator') : text('设置认证器', 'Set up authenticator') }}</button>
        <button v-if="mfa.enabled" type="button" class="btn-danger" :disabled="busy" @click="changeMfa('disable')">{{ text('关闭双重验证', 'Disable verification') }}</button></div>
      </form>
      <form v-if="pending" @submit.prevent="confirmMfa">
        <p>{{ text('在认证器中添加此密钥，再输入验证码确认。密钥只在此时展示。', 'Add this key to your authenticator, then enter a code to confirm. The key is shown only during setup.') }}</p>
        <code class="secret">{{ pending.secret }}</code>
        <a :href="pending.otpauth_uri" class="btn-secondary">{{ text('在认证器中打开', 'Open in authenticator') }}</a>
        <label>{{ text('六位验证码', 'Six-digit code') }}<input v-model="confirmCode" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required /></label>
        <button class="btn-primary" :disabled="busy">{{ text('确认启用', 'Confirm setup') }}</button>
      </form>
      <div v-if="recoveryCodes.length">
        <p>{{ text('将这些一次性恢复码保存在安全的地方。离开此页面后无法再次查看。其他登录会话已撤销。', 'Save these one-use recovery codes securely. They will not be shown again. Other sessions have been revoked.') }}</p>
        <pre class="secret">{{ recoveryCodes.join('\n') }}</pre>
        <button class="btn-secondary" @click="downloadRecovery">{{ text('下载恢复码', 'Download recovery codes') }}</button>
        <button class="btn-ghost" @click="recoveryCodes = []">{{ text('我已保存', 'I have saved them') }}</button>
      </div>
    </section>
    <section class="card">
      <h3>{{ text('修改密码', 'Change password') }}</h3>
      <p class="text-muted">{{ text('修改后会撤销所有会话，需要重新登录。', 'Changing your password revokes all sessions and requires signing in again.') }}</p>
      <form @submit.prevent="changePassword">
        <label>{{ text('当前密码', 'Current password') }}<input v-model="oldPassword" type="password" autocomplete="current-password" required /></label>
        <label>{{ text('新密码（至少 8 位）', 'New password (at least 8 characters)') }}<input v-model="newPassword" type="password" autocomplete="new-password" minlength="8" required /></label>
        <label v-if="mfa.enabled">{{ text('验证码或恢复码', 'Authenticator or recovery code') }}<input v-model="passwordCode" autocomplete="one-time-code" required /></label>
        <button class="btn-primary" :disabled="busy">{{ text('更新密码', 'Update password') }}</button>
      </form>
    </section>
    <PreferencesSyncPanel />
    <section class="card">
      <div class="flex-between"><h3>{{ text('登录会话', 'Sign-in sessions') }}</h3><button class="btn-ghost" :disabled="busy" @click="run(load)">{{ text('刷新', 'Refresh') }}</button></div>
      <div v-for="session in sessions" :key="session.id" class="session">
        <div><strong>{{ session.current ? text('当前会话', 'This session') : session.method }}</strong><p class="text-sm text-muted">{{ session.client_label || '—' }}</p><p class="text-sm">{{ text('创建', 'Created') }} {{ when(session.created_at) }} · {{ text('最近使用', 'Last used') }} {{ when(session.last_seen_at) }}</p></div>
        <span v-if="session.revoked_at" class="text-muted">{{ text('已撤销', 'Revoked') }}</span>
        <button v-else class="btn-danger btn-sm" :disabled="busy" @click="revoke(session)">{{ text('撤销', 'Revoke') }}</button>
      </div>
      <button class="btn-danger" :disabled="busy" @click="revokeAll">{{ text('注销所有会话', 'Sign out all sessions') }}</button>
    </section>
  </div>
</template>
<script setup lang="ts">
import PreferencesSyncPanel from '../components/PreferencesSyncPanel.vue'
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import client from '../api/client'
import { useAuthStore } from '../stores/auth'
import { useI18n } from '../composables/i18n'
interface Session { id: string; method: string; client_label: string; created_at: number; last_seen_at: number; current: boolean; revoked_at: number | null }
const auth = useAuthStore(), router = useRouter(), { locale } = useI18n()
const text = (zh: string, en: string) => locale.value === 'zh' ? zh : en
const busy = ref(false), error = ref(''), message = ref('')
const mfa = ref({ enabled: false, pending: false, recovery_codes_remaining: 0 })
const sessions = ref<Session[]>([]), pending = ref<{ secret: string; otpauth_uri: string } | null>(null), recoveryCodes = ref<string[]>([])
const password = ref(''), code = ref(''), confirmCode = ref(''), oldPassword = ref(''), newPassword = ref(''), passwordCode = ref('')
const when = (seconds: number) => new Date(seconds * 1000).toLocaleString()
async function run(action: () => Promise<void>) {
  if (busy.value) return
  busy.value = true; error.value = ''; message.value = ''
  try { await action() } catch (e: any) { error.value = e.response?.data?.error || e.message || text('操作失败', 'Operation failed') }
  finally { busy.value = false }
}
async function load() {
  const [status, list] = await Promise.all([client.get('/auth/mfa'), client.get('/auth/sessions')])
  mfa.value = status.data; sessions.value = list.data
}
function changeMfa(action: 'setup' | 'disable') { return run(async () => {
  const { data } = await client.post(`/auth/mfa/${action}`, { password: password.value, code: code.value })
  password.value = ''; code.value = ''
  if (action === 'setup') pending.value = data
  else message.value = text('双重验证已关闭，其他会话已撤销。', 'Verification disabled. Other sessions have been revoked.')
  await load()
}) }
function confirmMfa() { return run(async () => {
  const { data } = await client.post('/auth/mfa/confirm', { code: confirmCode.value })
  recoveryCodes.value = data.recovery_codes; pending.value = null; confirmCode.value = ''; await load()
}) }
function downloadRecovery() {
  const url = URL.createObjectURL(new Blob([recoveryCodes.value.join('\n') + '\n'], { type: 'text/plain' }))
  const link = document.createElement('a'); link.href = url; link.download = 'sb-easy-recovery-codes.txt'; link.click(); URL.revokeObjectURL(url)
}
function changePassword() { return run(async () => {
  await client.post('/auth/password', { password: oldPassword.value, new_password: newPassword.value, code: passwordCode.value })
  auth.clear(); await router.replace('/login')
}) }
function revoke(session: Session) { return run(async () => {
  await client.delete(`/auth/sessions/${session.id}`)
  if (session.current) { auth.clear(); await router.replace('/login') } else await load()
}) }
function revokeAll() { return run(async () => { await client.delete('/auth/sessions'); auth.clear(); await router.replace('/login') }) }
onMounted(() => run(load))
</script>
<style scoped>
.security-page { max-width: 900px; }
.card { margin-bottom: 1.2rem; padding: 1.5rem; }
h3 { margin-bottom: .8rem; }
form { max-width: 500px; }
label { display: grid; gap: .4rem; margin: 1rem 0; font-size: .9rem; }
.actions { display: flex; gap: .7rem; flex-wrap: wrap; }
.secret { display: block; background: var(--paper-bg); padding: 1rem; margin: 1rem 0; overflow-wrap: anywhere; white-space: pre-wrap; }
.session { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 1rem 0; border-bottom: 1px solid var(--paper-border); overflow-wrap: anywhere; }
.session:last-of-type { margin-bottom: 1rem; }
.notice { padding: 1rem; background: var(--accent-subtle); margin-bottom: 1rem; }
.error { color: var(--bad); }
</style>
