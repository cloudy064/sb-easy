<template>
  <section class="card sync-panel">
    <div class="flex-between">
      <h3>{{ zh ? '基础配置与设备差异' : 'Shared default and device changes' }}</h3>
      <button class="btn-secondary btn-sm" :disabled="busy" @click="refresh">{{ zh ? '检查更新' : 'Check updates' }}</button>
    </div>
    <p class="text-sm text-muted">{{ zh ? '服务端统一保存配置。空 patch 继承默认配置；只覆盖需要个性化的字段，其余字段继续跟随默认配置。' : 'The server owns configuration. An empty patch inherits the shared default; untouched fields keep following default updates.' }}</p>
    <router-link to="/profiles">{{ zh ? '编辑共享基础配置（Default）' : 'Edit shared default (Default)' }}</router-link>
    <p v-if="state" class="text-xs text-muted">{{ zh ? '基础版本' : 'Base version' }}: {{ state.base_version }} · {{ zh ? '设备版本' : 'Device version' }}: {{ state.patch_version }}</p>
    <p v-if="error" role="alert">{{ error }}</p>
    <template v-if="state">
      <label>{{ zh ? '设备 patch' : 'Device patch' }}<textarea v-model="draft" spellcheck="false" rows="12" :disabled="busy" /></label>
      <p class="text-xs text-muted">{{ zh ? 'null 删除字段；从 patch 移除字段恢复继承。数组整体替换，可增删列表项；覆盖后的列表不再合并默认列表。' : 'null deletes a field; removing it from the patch restores inheritance. Arrays replace the entire list, including additions and removals.' }}</p>
      <details v-if="runtimeSettings"><summary>{{ zh ? '设备运行设置' : 'Device runtime settings' }}</summary><textarea v-model="settingsDraft" spellcheck="false" rows="8" :disabled="busy" /></details>
      <div class="sync-actions">
        <button class="btn-primary" :disabled="busy || !!latest" @click="save">{{ zh ? '保存到服务器' : 'Save to server' }}</button>
        <button class="btn-secondary" :disabled="busy" @click="resetDraft">{{ zh ? '恢复默认（填入空 patch）' : 'Use default (clear draft patch)' }}</button>
      </div>
      <template v-if="latest">
        <p role="alert">{{ zh ? '服务器已有更新，草稿已保留。请核对最新配置，再选择重新编辑或采用服务器版本。' : 'The server changed. Your draft is preserved. Review the latest version before editing again or using the server version.' }}</p>
        <details open><summary>{{ zh ? '最新服务器差异' : 'Latest server changes' }}</summary><pre>{{ JSON.stringify({ patch: latest.patch, agent_settings: latest.agent_settings }, null, 2) }}</pre></details>
        <div class="sync-actions">
          <button class="btn-secondary" @click="reviewLatest">{{ zh ? '已核对，保留草稿继续编辑' : 'Reviewed; keep editing my draft' }}</button>
          <button class="btn-secondary" @click="useLatest">{{ zh ? '采用服务器版本' : 'Use server version' }}</button>
        </div>
      </template>
      <details><summary>{{ zh ? '共享基础配置（设备适配后）' : 'Shared default (adapted for device)' }}</summary><pre>{{ JSON.stringify(state.base, null, 2) }}</pre></details>
      <p class="text-xs text-muted">{{ zh ? '保存成功表示服务器已接收；客户端会定时同步，实际应用状态以设备上报为准。' : 'Saved means accepted by the server. The client syncs periodically; application status comes from the device.' }}</p>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import client from '../api/client'
import { useI18n } from '../composables/i18n'

interface ConfigState {
  base_version: number
  patch_version: number
  base: Record<string, unknown>
  patch: Record<string, unknown>
  config: Record<string, unknown>
  agent_settings: Record<string, unknown>
}
const props = withDefaults(defineProps<{ hostId: string; runtimeSettings?: boolean }>(), { runtimeSettings: true })
const emit = defineEmits<{ (e: 'updated', config: Record<string, unknown>): void }>()
const { locale } = useI18n()
const zh = computed(() => locale.value === 'zh')
const state = ref<ConfigState | null>(null)
const latest = ref<ConfigState | null>(null)
const draft = ref('{}')
const settingsDraft = ref('{}')
const busy = ref(false)
const error = ref('')
let generation = 0
const pretty = (value: unknown) => JSON.stringify(value, null, 2)

function accept(value: ConfigState) {
  state.value = value
  latest.value = null
  draft.value = pretty(value.patch)
  settingsDraft.value = pretty(value.agent_settings)
  emit('updated', value.config)
}
async function refresh() {
  const requested = ++generation
  busy.value = true
  error.value = ''
  try {
    const { data } = await client.get<ConfigState>(`/hosts/${encodeURIComponent(props.hostId)}/config-state`)
    if (requested !== generation) return
    if (state.value && (draft.value !== pretty(state.value.patch) || settingsDraft.value !== pretty(state.value.agent_settings))) {
      if (data.base_version !== state.value.base_version || data.patch_version !== state.value.patch_version) latest.value = data
    } else accept(data)
  } catch (e: any) {
    if (requested === generation) error.value = e?.response?.data?.error || e.message
  } finally { if (requested === generation) busy.value = false }
}
function object(text: string): Record<string, unknown> {
  const value = JSON.parse(text)
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(zh.value ? '请输入 JSON 对象' : 'Enter a JSON object')
  return value
}
async function save() {
  if (!state.value || busy.value || latest.value) return
  const requested = generation
  const hostId = props.hostId
  busy.value = true
  error.value = ''
  try {
    const { data } = await client.put<ConfigState>(`/hosts/${encodeURIComponent(hostId)}/config-state`, {
      base_version: state.value.base_version, patch_version: state.value.patch_version,
      patch: object(draft.value), agent_settings: object(settingsDraft.value),
    })
    if (requested === generation) accept(data)
  } catch (e: any) {
    if (requested !== generation) return
    error.value = e?.response?.data?.error || e.message
    if (e?.response?.status === 409) {
      try {
        const { data } = await client.get<ConfigState>(`/hosts/${encodeURIComponent(hostId)}/config-state`)
        if (requested === generation) latest.value = data
      } catch { /* preserve original error and draft; Check updates retries */ }
    }
  } finally { if (requested === generation) busy.value = false }
}
function resetDraft() { draft.value = '{}'; settingsDraft.value = '{}' }
function reviewLatest() { if (latest.value) { state.value = latest.value; latest.value = null; error.value = '' } }
function useLatest() { if (latest.value) { accept(latest.value); error.value = '' } }
watch(() => props.hostId, () => { state.value = null; latest.value = null; void refresh() }, { immediate: true })
</script>

<style scoped>
.sync-panel { margin-bottom: 1rem; }
.sync-panel h3 { margin: 0; }
.sync-panel label { display: block; margin-top: 1rem; }
.sync-panel textarea { display: block; width: 100%; box-sizing: border-box; font-family: var(--font-mono); margin-top: .5rem; }
.sync-panel details { margin-top: 1rem; }
.sync-panel pre { overflow: auto; max-height: 24rem; font-size: .75rem; }
.sync-actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: 1rem; }
</style>
