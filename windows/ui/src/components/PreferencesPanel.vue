<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue'
import { BridgeError, type NativeBridge } from '../lib/bridge'
import { validPreferencesEnvelope, type PreferencesCloud, type PreferencesEnvelope, type PreferencesPreview } from '../lib/protocol'
const props = defineProps<{ bridge: NativeBridge; disabled: boolean; configured: boolean; running: boolean }>()
const emit = defineEmits<{ busy: [value: boolean]; applied: [] }>()
const password = ref(''), accountPassword = ref(''), code = ref(''), server = ref(''), username = ref('')
const busy = ref(false), notice = ref(''), failed = ref(false)
const envelope = ref<PreferencesEnvelope>(), exported = ref(''), preview = ref<PreferencesPreview>(), cloud = ref<PreferencesCloud>()
const confirmDelete = ref(false), fileName = ref('')
let alive = true
async function action(task: () => Promise<void>) {
  if (busy.value || props.disabled) return
  busy.value = true; emit('busy', true); notice.value = ''; failed.value = false
  try { await task() }
  catch (error) {
    failed.value = true; notice.value = error instanceof Error ? error.message : '偏好操作未完成。'
    if (error instanceof BridgeError && error.code === 'PREFERENCES_CONFLICT' && cloud.value) cloud.value = { ...cloud.value, revision_known: false }
    if (error instanceof BridgeError && error.code === 'PREFERENCES_AUTH_REQUIRED') cloud.value = undefined
  } finally { password.value = ''; accountPassword.value = ''; code.value = ''; busy.value = false; if (alive) emit('busy', false) }
}
async function exportFile() {
  await action(async () => {
    const result = await props.bridge.request('preferences.export', { password: password.value }, { timeoutMs: 30000 })
    exported.value = JSON.stringify(result.envelope, null, 2)
    const url = URL.createObjectURL(new Blob([exported.value], { type: 'application/json' }))
    const link = document.createElement('a'); link.href = url; link.download = 'sb-easy-windows-preferences.json'; link.click()
    setTimeout(() => URL.revokeObjectURL(url), 30000)
    notice.value = '加密存档已生成。请保存文件，并单独保管密码。'
  })
}
async function chooseFile(event: Event) {
  const input = event.target as HTMLInputElement, file = input.files?.[0]
  preview.value = undefined; envelope.value = undefined; fileName.value = ''; notice.value = ''; failed.value = false
  if (!file) return
  try {
    if (file.size > 900 * 1024) throw new Error('加密文件不能超过 900 KiB。')
    const parsed: unknown = JSON.parse(await file.text())
    if (!validPreferencesEnvelope(parsed)) throw new Error('文件不是受支持的加密偏好存档。')
    envelope.value = parsed; fileName.value = file.name
  } catch (error) { failed.value = true; notice.value = error instanceof Error ? error.message : '无法读取文件。' }
  input.value = ''
}
async function previewArchive(remote = false) {
  await action(async () => {
    const selected = remote ? cloud.value?.envelope : envelope.value
    if (!selected) throw new Error('请先选择本地存档或读取远端存档。')
    preview.value = await props.bridge.request('preferences.preview', { password: password.value, envelope: selected }, { timeoutMs: 45000 })
    notice.value = '预览已就绪，确认后才会替换本机通用偏好。'
  })
}
async function applyArchive() {
  const value = preview.value
  if (!value) return
  let applied = false
  await action(async () => {
    await props.bridge.request('preferences.apply', { preview_id: value.preview_id }, { timeoutMs: 45000 })
    preview.value = undefined; notice.value = '偏好已应用；设备注册、进程分组与安全设置已保留。'; applied = true
  })
  if (applied) emit('applied')
}
async function login() {
  await action(async () => { cloud.value = await props.bridge.request('preferences.cloud.login', { server: server.value.trim(), username: username.value, password: accountPassword.value }, { timeoutMs: 45000 }); notice.value = cloud.value.mfa_required ? '请输入验证器动态码或恢复码。' : '已登录面板账号。请读取远端状态后再上传。' })
}
async function mfa() {
  if (!cloud.value?.session_id) return
  await action(async () => { cloud.value = await props.bridge.request('preferences.cloud.mfa', { session_id: cloud.value!.session_id, code: code.value.trim() }, { timeoutMs: 30000 }); notice.value = '已完成验证。请读取远端状态后再上传。' })
}
async function getRemote() {
  if (!cloud.value?.session_id) return
  await action(async () => { cloud.value = await props.bridge.request('preferences.cloud.get', { session_id: cloud.value!.session_id }, { timeoutMs: 30000 }); confirmDelete.value = false; notice.value = cloud.value.envelope ? '已读取远端加密存档。可输入存档密码进行预览。' : cloud.value.deleted ? '远端存档已删除。后续上传将基于此删除版本创建新存档。' : '此账号尚无 Windows 偏好存档。' })
}
async function upload() {
  if (!cloud.value?.revision_known) return
  await action(async () => { cloud.value = await props.bridge.request('preferences.cloud.put', { session_id: cloud.value!.session_id, revision: cloud.value!.revision, password: password.value }, { timeoutMs: 45000 }); notice.value = '已加密上传本机偏好。面板仅保存密文。' })
}
async function removeRemote() {
  if (!cloud.value?.revision_known) return
  await action(async () => { cloud.value = await props.bridge.request('preferences.cloud.delete', { session_id: cloud.value!.session_id, revision: cloud.value!.revision }, { timeoutMs: 30000 }); confirmDelete.value = false; notice.value = '远端加密存档已删除。' })
}
async function logout() {
  if (!cloud.value?.session_id) return
  const session = cloud.value.session_id
  await action(async () => { try { await props.bridge.request('preferences.cloud.logout', { session_id: session }, { timeoutMs: 30000 }); notice.value = '面板账号已退出。' } finally { cloud.value = undefined } })
}
onBeforeUnmount(() => { alive = false; password.value = ''; accountPassword.value = ''; code.value = ''; envelope.value = undefined; exported.value = ''; preview.value = undefined })
</script>

<template>
  <section class="panel preferences-panel" aria-labelledby="preferences-title">
    <div class="section-heading"><h2 id="preferences-title">加密偏好与个人同步</h2></div>
    <p class="input-hint">同步本机订阅、通用出口选择与健康策略。设备注册、域名和进程自定义分组、自动连接、防泄漏、抓包和证书会留在本机。存档密码仅在本次操作中使用。</p>
    <label class="preferences-field">存档密码<input v-model="password" type="password" autocomplete="new-password" maxlength="1024" :disabled="disabled" placeholder="至少 12 个 UTF-8 字节，建议使用长密码" data-testid="preferences-password" /></label>
    <div class="preferences-actions"><button class="secondary-button" :disabled="disabled || !configured || !password" @click="exportFile" data-testid="preferences-export">导出加密文件</button><label class="secondary-button preferences-file" :class="{ disabled }">选择加密文件<input type="file" accept="application/json,.json" :disabled="disabled" @change="chooseFile" data-testid="preferences-file" /></label><button class="secondary-button" :disabled="disabled || !envelope || !password" @click="previewArchive(false)" data-testid="preferences-preview">解密并预览</button></div>
    <p v-if="fileName" class="input-hint">已选择：{{ fileName }}</p>
    <details v-if="exported" class="preferences-export"><summary>查看加密文件内容</summary><p class="input-hint">如果下载被系统阻止，可复制以下密文另存为 JSON 文件。</p><textarea :value="exported" readonly rows="4" aria-label="导出的加密存档" /></details>
    <div v-if="preview" class="preferences-preview" role="region" aria-label="偏好导入预览"><h3>确认导入</h3><p>{{ preview.subscription_names.length }} 个订阅 · {{ preview.node_count }} 个节点 · {{ preview.routing_count }} 个通用出口选择</p><p v-if="preview.subscription_names.length">{{ preview.subscription_names.join('、') }}</p><p class="input-hint">将替换本机订阅与通用偏好，设备专属设置保留。{{ running ? '正在连接，应用时会验证配置并重新连接，已有连接可能中断。' : '导入不会自动连接。' }} 预览 5 分钟内有效，本机内容变化后需重新预览。</p><div class="preferences-actions"><button class="primary-button" :disabled="disabled" @click="applyArchive" data-testid="preferences-apply">确认应用偏好</button><button class="text-button" :disabled="disabled" @click="preview = undefined">取消导入</button></div></div>
    <div class="preferences-cloud">
      <h3>同步到自己的面板账号</h3><p class="input-hint">使用 HTTPS 面板地址及账号登录；设备注册码不能用于个人同步。账号会话不写入磁盘；重新打开窗口后需登录，每次上传或解密都需重新输入存档密码。</p>
      <form v-if="!cloud?.connected && !cloud?.mfa_required" class="preferences-login" @submit.prevent="login"><label class="preferences-field">HTTPS 面板地址<input v-model="server" type="url" required placeholder="https://panel.example.com" :disabled="disabled" autocomplete="url" /></label><label class="preferences-field">面板用户名<input v-model="username" required maxlength="256" :disabled="disabled" autocomplete="username" /></label><label class="preferences-field">面板账号密码<input v-model="accountPassword" type="password" required maxlength="4096" :disabled="disabled" autocomplete="current-password" /></label><button class="secondary-button" :disabled="disabled" data-testid="preferences-login">登录面板账号</button></form>
      <form v-else-if="cloud.mfa_required" class="preferences-login" @submit.prevent="mfa"><label class="preferences-field">动态码或恢复码<input v-model="code" required maxlength="128" :disabled="disabled" autocomplete="one-time-code" /></label><button class="secondary-button" :disabled="disabled">完成登录验证</button></form>
      <template v-else-if="cloud?.connected"><p class="preferences-account">{{ cloud.username }} · {{ cloud.server }}</p><div class="preferences-actions"><button class="secondary-button" :disabled="disabled" @click="getRemote" data-testid="preferences-cloud-get">读取远端状态</button><button class="secondary-button" :disabled="disabled || !configured || !cloud.revision_known || !password" @click="upload" data-testid="preferences-cloud-put">加密上传本机偏好</button><button class="secondary-button" :disabled="disabled || !cloud.envelope || !password" @click="previewArchive(true)">预览远端存档</button><button class="text-button" :disabled="disabled" @click="logout">退出账号</button></div><p class="input-hint">{{ cloud.revision_known ? `已读取版本 ${cloud.revision}${cloud.updated_at ? ' · ' + new Date(cloud.updated_at * 1000).toLocaleString('zh-CN') : ''}` : '需读取远端状态；冲突时不会覆盖其他设备的修改。' }}</p><button v-if="cloud.envelope && cloud.revision_known && !confirmDelete" class="text-button" :disabled="disabled" @click="confirmDelete = true">删除远端存档</button><div v-if="confirmDelete" class="preferences-actions"><span>确认删除远端加密存档？本机偏好保留。</span><button class="danger-button" :disabled="disabled" @click="removeRemote">确认删除</button><button class="text-button" :disabled="disabled" @click="confirmDelete = false">取消</button></div></template>
    </div>
    <p v-if="notice" :class="failed ? 'diagnostic-error' : 'input-hint'" :role="failed ? 'alert' : 'status'">{{ notice }}</p>
  </section>
</template>

<style scoped>
.preferences-panel { margin-top:24px; padding:24px; }.preferences-field { display:grid; gap:7px; font-size:12px; color:var(--secondary); margin:14px 0; }.preferences-field input,.preferences-export textarea { width:100%; min-width:0; box-sizing:border-box; border:1px solid var(--border); background:var(--paper); color:var(--ink); padding:10px; border-radius:8px; }.preferences-actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-top:14px; }.preferences-file { position:relative; display:inline-flex; cursor:pointer; }.preferences-file input { position:absolute; opacity:0; inset:0; width:100%; cursor:pointer; }.preferences-file.disabled { opacity:.5; cursor:default; }.preferences-cloud { border-top:1px solid var(--border); margin-top:22px; padding-top:20px; }.preferences-cloud h3,.preferences-preview h3 { margin:0; font-size:14px; }.preferences-login { max-width:620px; }.preferences-preview { margin-top:20px; padding:18px; border:1px solid var(--accent); background:var(--accent-bg); border-radius:10px; font-size:13px; }.preferences-account { overflow-wrap:anywhere; font-size:13px; }.preferences-export { margin-top:18px; font-size:12px; }.preferences-export textarea { font-family:monospace; resize:vertical; }
</style>
