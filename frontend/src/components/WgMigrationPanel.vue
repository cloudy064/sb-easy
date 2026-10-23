<template>
  <section class="card">
    <h3>wg-easy {{ tr('迁移', 'migration') }}</h3>
    <p class="text-sm text-muted">{{ tr('导入 v14 的 wg0.json，保留服务端身份和客户端地址。v15 SQLite 备份暂不支持。', 'Import a v14 wg0.json while preserving server identity and client addresses. v15 SQLite backups are not supported.') }}</p>
    <p class="text-xs text-muted">{{ tr('预览不会修改数据。导入和回滚需要先设置 WG_ENABLED=false 并重启面板；检查公网地址、DNS 和防火墙后再启用 WireGuard。', 'Preview leaves data unchanged. Apply and rollback require restarting the panel with WG_ENABLED=false. Check the public endpoint, DNS and firewall before enabling WireGuard again.') }}</p>
    <div class="fields">
      <label>{{ tr('备份文件', 'Backup file') }}<input type="file" accept=".json,application/json" :disabled="busy" @change="readFile" /></label>
      <label>DNS<input v-model="dns" placeholder="1.1.1.1, 2606:4700:4700::1111" :disabled="busy" /></label>
      <label>Allowed IPs<input v-model="allowedIps" :disabled="busy" /></label>
      <label>Persistent keepalive (s)<input v-model.number="keepalive" type="number" min="0" max="65535" :disabled="busy" /></label>
    </div>
    <button class="btn-secondary btn-sm" :disabled="busy || !configuration" @click="preview">{{ tr('检查并预览', 'Check and preview') }}</button>
    <p v-if="message" class="text-sm" role="status">{{ message }}</p>
    <p v-if="error" class="error text-sm" role="alert">{{ error }}</p>
    <div v-if="report" class="preview">
      <p><strong>{{ report.server_address }}</strong> · {{ tr('新增', 'Add') }} {{ report.added }} · {{ tr('已有', 'Already present') }} {{ report.skipped }}</p>
      <p class="text-xs key">{{ tr('服务端公钥', 'Server public key') }}: {{ report.server_public_key }}</p>
      <ul v-if="report.conflicts.length"><li v-for="conflict in report.conflicts" :key="conflict" class="error">{{ conflict }}</li></ul>
      <p v-if="report.wireguard_running" class="error text-sm">{{ tr('WireGuard 当前已启用。请先停用并重启面板，再重新预览。', 'WireGuard is enabled. Disable it, restart the panel and preview again.') }}</p>
      <div class="table-scroll">
        <table><thead><tr><th>{{ tr('名称', 'Name') }}</th><th>{{ tr('地址', 'Address') }}</th><th>{{ tr('状态', 'Status') }}</th><th>{{ tr('导入结果', 'Action') }}</th></tr></thead>
          <tbody><tr v-for="row in report.clients" :key="row.id"><td>{{ row.name }}<small v-if="!row.has_private_key">{{ tr('仅公钥：继续使用原客户端配置', 'Public key only: keep the original client config') }}</small></td><td>{{ row.address }}</td><td>{{ row.enabled ? tr('启用', 'Enabled') : tr('停用', 'Disabled') }}</td><td>{{ actionLabel(row.action) }}</td></tr></tbody>
        </table>
      </div>
      <button v-if="report.status === 'preview'" class="btn-primary btn-sm" :disabled="busy || !report.can_import || report.wireguard_running" @click="apply">{{ tr('应用以上导入', 'Apply this import') }}</button>
    </div>
    <div v-if="history.length" class="history">
      <h4>{{ tr('最近迁移', 'Recent imports') }}</h4>
      <p class="text-xs text-muted">{{ tr('回滚会移除该次新增客户端并恢复原服务端设置。导入后配置发生变化时会拒绝回滚，以保留后续修改。', 'Rollback removes the imported clients and restores prior server settings. It is refused if WireGuard data has changed since the import.') }}</p>
      <div v-for="item in history" :key="item.id" class="history-row">
        <span>{{ item.created_at }} · {{ item.added }} {{ tr('个客户端', 'clients') }} · {{ item.status === 'applied' ? tr('已导入', 'Imported') : tr('已回滚', 'Rolled back') }}</span>
        <button v-if="item.status === 'applied' && rollbackId !== item.id" class="btn-secondary btn-sm" :disabled="busy" @click="rollbackId = item.id">{{ tr('回滚…', 'Rollback…') }}</button>
        <template v-if="rollbackId === item.id">
          <button class="btn-danger btn-sm" :disabled="busy" @click="rollback(item.id)">{{ tr('确认回滚此迁移', 'Confirm this rollback') }}</button>
          <button class="btn-secondary btn-sm" :disabled="busy" @click="rollbackId = ''">{{ tr('取消', 'Cancel') }}</button>
        </template>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useI18n } from '../composables/i18n'
import client from '../api/client'

const { locale } = useI18n()
const tr = (zh: string, en: string) => locale.value === 'zh' ? zh : en
interface Preview {
  status: string; preview_digest: string; can_import: boolean; wireguard_running: boolean
  server_address: string; server_public_key: string; added: number; skipped: number; conflicts: string[]
  clients: { id: string; name: string; address: string; enabled: boolean; has_private_key: boolean; action: string }[]
}
const path = '/system/migrate/wg-easy'
const configuration = ref<Record<string, unknown> | null>(null)
const dns = ref('1.1.1.1'), allowedIps = ref('0.0.0.0/0, ::/0'), keepalive = ref(25)
const report = ref<Preview | null>(null), busy = ref(false), error = ref(''), message = ref(''), rollbackId = ref('')
const history = ref<{ id: string; created_at: string; status: string; added: number }[]>([])
watch([dns, allowedIps, keepalive], () => { report.value = null })
function actionLabel(action: string) {
  return action === 'add' ? tr('新增', 'Add') : action === 'already_present' ? tr('保留已有', 'Keep existing') : tr('冲突', 'Conflict')
}
function errorText(cause: unknown) {
  const response = (cause as { response?: { data?: { error?: string; message?: string } } })?.response?.data
  return response?.error || response?.message || (cause instanceof Error ? cause.message : tr('操作失败', 'Operation failed'))
}
async function readFile(event: Event) {
  configuration.value = null; report.value = null; message.value = ''; error.value = ''
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  try {
    if (file.size > 1024 * 1024) throw new Error(tr('备份文件不能超过 1 MiB', 'Backup file must be at most 1 MiB'))
    const parsed = JSON.parse(await file.text())
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') throw new Error(tr('需要 JSON 对象', 'Expected a JSON object'))
    configuration.value = parsed
  } catch (cause) { error.value = errorText(cause) }
}
function payload(action: string) {
  return { action, format: 'wg-easy-v14', configuration: configuration.value,
    options: { dns: dns.value, allowed_ips: allowedIps.value, persistent_keepalive: keepalive.value },
    preview_digest: report.value?.preview_digest }
}
async function loadHistory() { history.value = (await client.get(path)).data }
async function preview() {
  busy.value = true; error.value = ''; message.value = ''
  try { report.value = (await client.post(path, payload('preview'))).data }
  catch (cause) { report.value = null; error.value = errorText(cause) }
  finally { busy.value = false }
}
async function apply() {
  busy.value = true; error.value = ''
  try {
    report.value = (await client.post(path, payload('apply'))).data
    message.value = tr('导入成功。检查公网地址、DNS 和防火墙后，设置 WG_ENABLED=true 并重启以启用。', 'Imported. Check the public endpoint, DNS and firewall, then restart with WG_ENABLED=true to activate.')
    configuration.value = null
    await loadHistory()
  } catch (cause) { error.value = errorText(cause); report.value = null }
  finally { busy.value = false }
}
async function rollback(id: string) {
  busy.value = true; error.value = ''
  try {
    await client.post(path, { action: 'rollback', migration_id: id })
    report.value = null; rollbackId.value = ''
    message.value = tr('已回滚。重新启用 WireGuard 前请检查原服务端设置。', 'Rolled back. Review the restored server settings before enabling WireGuard.')
    await loadHistory()
  } catch (cause) { error.value = errorText(cause) }
  finally { busy.value = false }
}
onMounted(() => { loadHistory().catch(cause => { error.value = errorText(cause) }) })
</script>

<style scoped>
h3 { font-size: .95rem; margin-bottom: .5rem; }
p { margin: .5rem 0; }
.fields { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: .75rem; margin: 1rem 0; }
label { display: grid; gap: .3rem; font-size: .8rem; }
.error { color: var(--color-danger, #dc2626); }
.preview, .history { margin-top: 1rem; padding-top: .75rem; border-top: 1px solid var(--border, #e2e8f0); }
.key { overflow-wrap: anywhere; }
.table-scroll { overflow-x: auto; margin: .75rem 0; }
table { width: 100%; text-align: left; font-size: .8rem; }
th, td { padding: .4rem; }
small { display: block; color: var(--text-muted, #64748b); }
.history-row { display: flex; gap: .6rem; align-items: center; flex-wrap: wrap; margin: .5rem 0; font-size: .8rem; }
@media (max-width: 600px) { .fields { grid-template-columns: 1fr; } }
</style>
