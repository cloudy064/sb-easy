<template>
  <section class="card">
    <h3>{{ text('加密偏好迁移与同步', 'Encrypted preferences and sync') }}</h3>
    <p class="text-muted">{{ text('迁移面板的语言与主题。账户令牌、服务器密钥和设备配置不会包含在内。中心只保存密文；口令丢失后无法恢复。', 'Move panel language and theme preferences. Account tokens, server keys and device configurations are excluded. The server stores only ciphertext; a lost passphrase cannot be recovered.') }}</p>
    <p v-if="error" class="error" role="alert">{{ error }}</p><p v-if="message" role="status">{{ message }}</p>
    <label>{{ text('加密口令', 'Encryption passphrase') }}<input v-model="passphrase" type="password" autocomplete="off" minlength="12" /></label>
    <div class="actions"><button class="btn-secondary" :disabled="busy" @click="exportLocal">{{ text('导出加密文件', 'Export encrypted file') }}</button><button class="btn-secondary" :disabled="busy" @click="fileInput?.click()">{{ text('导入并预览', 'Import and preview') }}</button><input ref="fileInput" type="file" accept="application/json" hidden @change="importLocal" /></div>
    <hr />
    <p>{{ text('账户同步版本', 'Account sync revision') }}: {{ revision === null ? '—' : revision }} <span v-if="updatedAt">· {{ new Date(updatedAt * 1000).toLocaleString() }}</span></p>
    <p v-if="remoteDeleted" class="text-muted">{{ text('远端快照已删除。新的上传将从此版本继续。', 'The remote snapshot was deleted. A new upload continues from this revision.') }}</p>
    <div class="actions"><button class="btn-ghost" :disabled="busy" @click="run(fetchRemote)">{{ text('检查远端版本', 'Check remote revision') }}</button><button class="btn-primary" :disabled="busy || revision === null" @click="upload">{{ text('上传本机偏好', 'Upload local preferences') }}</button><button class="btn-secondary" :disabled="busy || !remote" @click="previewRemote">{{ text('下载并预览', 'Download and preview') }}</button><button class="btn-danger" :disabled="busy || !remote" @click="removeRemote">{{ text('删除远端快照', 'Delete remote snapshot') }}</button></div>
    <div v-if="pending" class="preview">
      <h4>{{ text('导入预览', 'Import preview') }}</h4>
      <p>{{ text('语言', 'Language') }}: {{ locale }} → {{ pending.locale }}<br />{{ text('主题', 'Theme') }}: {{ theme }} → {{ pending.theme }}</p>
      <button class="btn-primary" @click="applyPreview">{{ text('应用这些偏好', 'Apply these preferences') }}</button><button class="btn-ghost" @click="pending = null">{{ text('取消', 'Cancel') }}</button>
    </div>
  </section>
</template>
<script setup lang="ts">
import { onMounted, ref } from 'vue'
import client from '../api/client'
import { useI18n, setLocale } from '../composables/i18n'
import { useTheme, applyTheme } from '../composables/theme'
import { ARCHIVE_LIMIT, decryptArchive, encryptArchive, type SecureEnvelope } from '../lib/secureArchive'
interface Preferences { locale: 'zh' | 'en'; theme: 'light' | 'dark' }
const { locale } = useI18n(), { theme } = useTheme()
const text = (zh: string, en: string) => locale.value === 'zh' ? zh : en
const path = '/auth/preferences/web-personal'
const busy = ref(false), error = ref(''), message = ref(''), passphrase = ref('')
const fileInput = ref<HTMLInputElement | null>(null), pending = ref<Preferences | null>(null)
const revision = ref<number | null>(null), updatedAt = ref(0), remoteDeleted = ref(false), remote = ref<SecureEnvelope | null>(null)
const snapshot = () => ({ format: 'sb-easy.preferences.payload', version: 1, platform: 'web', preferences: { locale: locale.value, theme: theme.value } })
async function run(action: () => Promise<void>) {
  if (busy.value) return
  busy.value = true; error.value = ''; message.value = ''
  try { await action() } catch (e: any) { error.value = e.response?.status === 409 ? text('另一台设备已修改偏好。请检查远端版本并预览后再决定。', 'Another device changed these preferences. Check and preview the remote revision before saving.') : e.response?.data?.error || e.message }
  finally { busy.value = false }
}
async function fetchRemote() {
  try { const { data } = await client.get(path); revision.value = data.revision; updatedAt.value = data.updated_at; remote.value = data.envelope; remoteDeleted.value = data.deleted === true }
  catch (e: any) { if (e.response?.status !== 404) throw e; revision.value = 0; updatedAt.value = 0; remote.value = null; remoteDeleted.value = false }
}
async function preview(value: unknown) {
  const payload = await decryptArchive(value, passphrase.value) as { format?: string; version?: number; platform?: string; preferences?: Partial<Preferences> }
  const prefs = payload?.preferences
  if (payload?.format !== 'sb-easy.preferences.payload' || payload.version !== 1 || payload.platform !== 'web' || !prefs || Object.keys(prefs).sort().join(',') !== 'locale,theme' || !['zh', 'en'].includes(String(prefs.locale)) || !['light', 'dark'].includes(String(prefs.theme))) throw new Error(text('此文件不是受支持的面板偏好。请在对应客户端导入客户端文件。', 'This is not a supported panel preferences file. Import client archives in their matching client.'))
  pending.value = { locale: prefs.locale!, theme: prefs.theme! }; passphrase.value = ''
}
function exportLocal() { return run(async () => {
  const envelope = await encryptArchive(snapshot(), passphrase.value); passphrase.value = ''
  const url = URL.createObjectURL(new Blob([JSON.stringify(envelope)], { type: 'application/json' }))
  const link = document.createElement('a'); link.href = url; link.download = 'sb-easy-preferences.encrypted.json'; link.click(); URL.revokeObjectURL(url)
}) }
async function importLocal(event: Event) {
  const input = event.target as HTMLInputElement, file = input.files?.[0]; if (!file) return
  await run(async () => { if (file.size > ARCHIVE_LIMIT) throw new Error('Archive exceeds 1 MiB'); await preview(JSON.parse(await file.text())) }); input.value = ''
}
function upload() { return run(async () => {
  if (revision.value === null) return
  const envelope = await encryptArchive(snapshot(), passphrase.value); passphrase.value = ''
  const { data } = await client.put(path, envelope, { headers: { 'If-Match': `"${revision.value}"` } })
  revision.value = data.revision; updatedAt.value = data.updated_at; remote.value = data.envelope; remoteDeleted.value = false; message.value = text('加密偏好已上传。', 'Encrypted preferences uploaded.')
}) }
function previewRemote() { return run(async () => { await fetchRemote(); if (!remote.value) throw new Error(text('远端快照已删除', 'Remote snapshot was deleted')); await preview(remote.value) }) }
function removeRemote() { return run(async () => { const { data } = await client.delete(path, { headers: { 'If-Match': `"${revision.value}"` } }); revision.value = data.revision; updatedAt.value = data.updated_at; remote.value = null; remoteDeleted.value = true }) }
function applyPreview() { if (!pending.value) return; setLocale(pending.value.locale); applyTheme(pending.value.theme); pending.value = null; message.value = text('偏好已应用。', 'Preferences applied.') }
onMounted(() => run(fetchRemote))
</script>
<style scoped>
h3 { margin-bottom: .8rem; }
label { display: grid; gap: .4rem; max-width: 500px; margin: 1rem 0; }
.actions { display: flex; flex-wrap: wrap; gap: .6rem; margin: 1rem 0; }
.preview { background: var(--paper-bg); padding: 1rem; margin-top: 1rem; }
.error { color: var(--bad); }
hr { border: 0; border-top: 1px solid var(--paper-border); margin: 1.5rem 0; }
</style>
