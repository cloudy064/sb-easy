<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.profiles.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.profiles.desc') }}</p>
      </div>
      <button class="btn-primary" @click="openCreate">{{ t('profiles.add') }}</button>
    </div>

    <div v-if="loading" class="loading-center"><div class="spinner"></div></div>
    <div v-else class="section-stack">
      <article v-for="p in store.profiles" :key="p.id" class="card profile-card">
        <div class="flex-between">
          <div>
            <h3 class="profile-name">{{ p.name }}</h3>
            <span class="profile-id">{{ p.id }}<span v-if="p.id === 'default'" class="badge badge-gray" style="margin-left:.5rem">{{ t('profiles.builtin') }}</span></span>
          </div>
          <div class="flex-center gap-2">
            <button class="btn-ghost btn-sm" @click="openEdit(p)">{{ t('profiles.edit') }}</button>
            <button v-if="p.id !== 'default'" class="btn-danger btn-sm" @click="deleteTarget = p">{{ t('action.delete') }}</button>
          </div>
        </div>
        <p class="profile-summary text-xs text-muted">{{ summarize(p.template) }}</p>
      </article>
    </div>

    <!-- Editor -->
    <div v-if="editor.open" class="modal-overlay" @click.self="editor.open = false">
      <div class="modal modal-wide">
        <h3>{{ editor.id ? t('profiles.edit') : t('profiles.add') }}</h3>
        <div class="form-group"><label>{{ t('profiles.name') }}</label><input v-model="editor.name" placeholder="e.g. Exit node (mixed only)" /></div>
        <div class="form-group">
          <label>{{ t('profiles.template') }}</label>
          <textarea v-model="editor.text" class="json-editor" spellcheck="false" @input="editor.error = ''"></textarea>
        </div>
        <p class="text-xs" :class="editor.error ? 'json-err' : 'text-muted'">
          {{ editor.error || t('profiles.template.hint') }}
        </p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="editor.open = false">{{ t('action.cancel') }}</button>
          <button class="btn-primary" @click="save">{{ t('action.save') }}</button>
        </div>
      </div>
    </div>

    <!-- Delete -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal">
        <h3>{{ t('profiles.delete.q') }} &ldquo;{{ deleteTarget.name }}&rdquo;?</h3>
        <p class="text-sm text-muted">{{ t('profiles.delete.hint') }}</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="deleteTarget = null">{{ t('action.cancel') }}</button>
          <button class="btn-danger" @click="doDelete">{{ t('action.delete') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from '../composables/i18n'
import { useHostsStore } from '../stores/hosts'
import type { ConfigProfile } from '../types'

const { t } = useI18n()
const store = useHostsStore()
const loading = ref(true)
const deleteTarget = ref<ConfigProfile | null>(null)

const editor = ref({ open: false, id: '', name: '', text: '', error: '' })

const TEMPLATE_SKELETON = {
  log: { level: 'info', timestamp: true },
  dns: { servers: [], final: '', strategy: 'prefer_ipv4' },
  inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '0.0.0.0', listen_port: 7890 }],
  route: { rules: [], final: 'Proxy', auto_detect_interface: true },
}

onMounted(async () => {
  await store.fetchProfiles()
  loading.value = false
})

function summarize(template: string): string {
  try {
    const t = JSON.parse(template)
    const inbounds = (t.inbounds || []).map((i: any) => i.type).join(', ')
    const rules = (t.route?.rules || []).length
    return `inbounds: ${inbounds || '—'} · route rules: ${rules} · final: ${t.route?.final ?? '—'}`
  } catch {
    return 'invalid template'
  }
}

function openCreate() {
  editor.value = { open: true, id: '', name: '', text: JSON.stringify(TEMPLATE_SKELETON, null, 2), error: '' }
}
function openEdit(p: ConfigProfile) {
  let text = p.template
  try { text = JSON.stringify(JSON.parse(p.template), null, 2) } catch { /* keep raw */ }
  editor.value = { open: true, id: p.id, name: p.name, text, error: '' }
}

async function save() {
  let parsed: unknown
  try {
    parsed = JSON.parse(editor.value.text)
  } catch (e: any) {
    editor.value.error = t('profiles.template.invalid') + ': ' + e.message
    return
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    editor.value.error = t('profiles.template.notobj')
    return
  }
  try {
    if (editor.value.id) await store.updateProfile(editor.value.id, editor.value.name, parsed)
    else await store.createProfile(editor.value.name, parsed)
    editor.value.open = false
  } catch (e: any) {
    editor.value.error = e?.response?.data?.error || 'Save failed'
  }
}

async function doDelete() {
  if (!deleteTarget.value) return
  await store.deleteProfile(deleteTarget.value.id)
  deleteTarget.value = null
}
</script>

<style scoped>
.profile-card { padding: 1.5rem; display: flex; flex-direction: column; gap: 0.75rem; }
.profile-name { font-size: 0.95rem; font-weight: 640; color: var(--ink-primary); }
.profile-id { font-family: var(--font-mono); font-size: 0.7rem; color: var(--ink-muted); }
.profile-summary { font-family: var(--font-mono); }
.modal-wide { max-width: 720px; width: 92vw; }
.json-editor {
  width: 100%; min-height: 360px; resize: vertical;
  font-family: var(--font-mono); font-size: 0.74rem; line-height: 1.55;
  background: var(--paper-bg); border: 1px solid var(--paper-border);
  border-radius: var(--radius-sm); padding: 0.75rem; color: var(--ink-primary);
}
.json-err { color: var(--bad); }
</style>
