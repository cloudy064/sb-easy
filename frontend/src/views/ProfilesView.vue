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

        <div class="tabs">
          <button :class="['tab', { active: editor.mode === 'form' }]" @click="switchMode('form')">{{ t('profiles.tab.form') }}</button>
          <button :class="['tab', { active: editor.mode === 'raw' }]" @click="switchMode('raw')">{{ t('profiles.tab.raw') }}</button>
        </div>

        <!-- FORM MODE -->
        <div v-if="editor.mode === 'form'" class="form-body">
          <div class="form-group">
            <label>{{ t('profiles.log') }}</label>
            <select v-model="model.log.level">
              <option v-for="lv in ['trace','debug','info','warn','error','fatal']" :key="lv" :value="lv">{{ lv }}</option>
            </select>
          </div>

          <!-- Inbounds -->
          <div class="section-block">
            <div class="flex-between"><h4>{{ t('profiles.inbounds') }}</h4><button class="btn-ghost btn-xs" @click="addInbound">+ {{ t('profiles.inbound.add') }}</button></div>
            <div v-for="(inb, i) in model.inbounds" :key="i" class="row-card">
              <div class="row-grid">
                <select v-model="inb.type">
                  <option v-for="tp in ['tun','mixed','http','socks']" :key="tp" :value="tp">{{ tp }}</option>
                </select>
                <input v-model="inb.tag" placeholder="tag" />
                <input v-if="inb.type !== 'tun'" v-model="inb.listen" placeholder="listen (0.0.0.0)" />
                <input v-if="inb.type !== 'tun'" v-model.number="inb.listen_port" type="number" placeholder="port" />
                <button class="btn-danger btn-xs" @click="model.inbounds.splice(i,1)">✕</button>
              </div>
              <div v-if="inb.type === 'tun'" class="row-grid-tun">
                <input :value="(inb.address||[]).join(', ')" @input="inb.address = splitList($event)" placeholder="address (172.20.0.1/30)" />
                <select v-model="inb.stack"><option value="mixed">mixed</option><option value="system">system</option><option value="gvisor">gvisor</option></select>
                <label class="chk"><input type="checkbox" v-model="inb.auto_route" /> auto_route</label>
                <label class="chk"><input type="checkbox" v-model="inb.strict_route" /> strict_route</label>
              </div>
            </div>
            <p v-if="!model.inbounds.length" class="text-xs text-muted">No inbounds.</p>
          </div>

          <!-- DNS -->
          <div class="section-block">
            <div class="flex-between"><h4>{{ t('profiles.dns') }}</h4><button class="btn-ghost btn-xs" @click="addDnsServer">+ {{ t('profiles.dns.add') }}</button></div>
            <div v-for="(s, i) in model.dns.servers" :key="i" class="row-grid">
              <input v-model="s.tag" placeholder="tag" />
              <select v-model="s.type"><option value="udp">udp</option><option value="tcp">tcp</option><option value="https">https</option><option value="tls">tls</option></select>
              <input v-model="s.server" placeholder="223.5.5.5" />
              <button class="btn-danger btn-xs" @click="model.dns.servers.splice(i,1)">✕</button>
            </div>
            <div class="row-grid" style="margin-top:.5rem">
              <input v-model="model.dns.final" placeholder="final (server tag)" />
              <select v-model="model.dns.strategy"><option value="prefer_ipv4">prefer_ipv4</option><option value="prefer_ipv6">prefer_ipv6</option><option value="ipv4_only">ipv4_only</option><option value="ipv6_only">ipv6_only</option></select>
            </div>
          </div>

          <!-- Route -->
          <div class="section-block">
            <h4>{{ t('profiles.route') }}</h4>
            <div class="row-grid">
              <input v-model="model.route.final" placeholder="final (auto)" list="re-ob-suggest" />
              <label class="chk"><input type="checkbox" v-model="model.route.auto_detect_interface" /> auto_detect_interface</label>
            </div>
            <div style="margin-top:.75rem">
              <span class="text-xs" style="font-weight:600;color:var(--ink-secondary)">{{ t('profiles.route.rules') }}</span>
              <RulesEditor :rules="model.route.rules" :outbound-suggestions="outboundSuggestions" style="margin-top:.4rem" />
            </div>
          </div>
        </div>

        <!-- RAW MODE -->
        <div v-else class="form-group">
          <label>{{ t('profiles.template') }}</label>
          <textarea v-model="editor.rawText" class="json-editor" spellcheck="false" @input="editor.error = ''"></textarea>
        </div>

        <p class="text-xs" :class="editor.error ? 'json-err' : 'text-muted'">{{ editor.error || t('profiles.template.hint') }}</p>
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
import { ref, reactive, computed, onMounted } from 'vue'
import { useI18n } from '../composables/i18n'
import { useHostsStore } from '../stores/hosts'
import { useProxyNodesStore } from '../stores/proxyNodes'
import RulesEditor from '../components/RulesEditor.vue'
import type { ConfigProfile } from '../types'

const { t } = useI18n()
const store = useHostsStore()
const nodesStore = useProxyNodesStore()

// Outbound targets a rule can point at: the built-in `auto` (fastest at
// startup), `direct`/`block`, and every individual proxy node by tag.
const outboundSuggestions = computed(() => [
  'auto', 'direct', 'block', ...nodesStore.nodes.map((n) => n.tag),
])
const loading = ref(true)
const deleteTarget = ref<ConfigProfile | null>(null)

const editor = ref({ open: false, id: '', name: '', mode: 'form' as 'form' | 'raw', rawText: '', error: '' })

// Structured working copy used by the form. Normalised so the template always
// has the sections the form binds to; the raw tab edits the same data as JSON.
const model = reactive<any>(emptyModel())

function emptyModel() {
  return {
    log: { level: 'info', timestamp: true },
    dns: { servers: [] as any[], final: '', strategy: 'prefer_ipv4' },
    inbounds: [] as any[],
    route: { rules: [] as any[], final: 'Proxy', auto_detect_interface: true },
  }
}

/** Ensure the parsed object has the sections the form expects, without dropping
 * any unknown keys the user may have in raw mode. */
function normalize(obj: any) {
  const m: any = obj && typeof obj === 'object' && !Array.isArray(obj) ? { ...obj } : {}
  m.log = m.log && typeof m.log === 'object' ? m.log : { level: 'info' }
  if (!m.log.level) m.log.level = 'info'
  m.dns = m.dns && typeof m.dns === 'object' ? m.dns : {}
  if (!Array.isArray(m.dns.servers)) m.dns.servers = []
  if (m.dns.final == null) m.dns.final = ''
  if (m.dns.strategy == null) m.dns.strategy = 'prefer_ipv4'
  if (!Array.isArray(m.inbounds)) m.inbounds = []
  m.route = m.route && typeof m.route === 'object' ? m.route : {}
  if (!Array.isArray(m.route.rules)) m.route.rules = []
  if (m.route.final == null) m.route.final = 'Proxy'
  if (m.route.auto_detect_interface == null) m.route.auto_detect_interface = true
  return m
}

function setModel(obj: any) {
  Object.keys(model).forEach((k) => delete (model as any)[k])
  Object.assign(model, normalize(obj))
}

function splitList(e: Event): string[] {
  return (e.target as HTMLInputElement).value.split(',').map((s) => s.trim()).filter(Boolean)
}

onMounted(async () => {
  await Promise.all([store.fetchProfiles(), nodesStore.fetchNodes()])
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
  setModel(emptyModel())
  model.inbounds.push({ type: 'mixed', tag: 'mixed-in', listen: '0.0.0.0', listen_port: 7890 })
  editor.value = { open: true, id: '', name: '', mode: 'form', rawText: '', error: '' }
}
function openEdit(p: ConfigProfile) {
  let obj: any = {}
  try { obj = JSON.parse(p.template) } catch { /* fall back to empty */ }
  setModel(obj)
  editor.value = { open: true, id: p.id, name: p.name, mode: 'form', rawText: '', error: '' }
}

function switchMode(mode: 'form' | 'raw') {
  if (mode === editor.value.mode) return
  if (mode === 'raw') {
    editor.value.rawText = JSON.stringify(model, null, 2)
    editor.value.error = ''
    editor.value.mode = 'raw'
  } else {
    // Parse raw back into the form; stay on raw if it's invalid.
    try {
      const parsed = JSON.parse(editor.value.rawText)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object')
      setModel(parsed)
      editor.value.error = ''
      editor.value.mode = 'form'
    } catch (e: any) {
      editor.value.error = t('profiles.template.invalid') + ': ' + e.message
    }
  }
}

async function save() {
  let payload: any
  if (editor.value.mode === 'raw') {
    try {
      payload = JSON.parse(editor.value.rawText)
    } catch (e: any) {
      editor.value.error = t('profiles.template.invalid') + ': ' + e.message
      return
    }
  } else {
    payload = JSON.parse(JSON.stringify(model)) // plain snapshot of the reactive model
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    editor.value.error = t('profiles.template.notobj')
    return
  }
  try {
    if (editor.value.id) await store.updateProfile(editor.value.id, editor.value.name, payload)
    else await store.createProfile(editor.value.name, payload)
    editor.value.open = false
  } catch (e: any) {
    editor.value.error = e?.response?.data?.error || 'Save failed'
  }
}

function addInbound() {
  model.inbounds.push({ type: 'mixed', tag: 'in-' + (model.inbounds.length + 1), listen: '0.0.0.0', listen_port: 1080 })
}
function addDnsServer() {
  model.dns.servers.push({ tag: 'dns-' + (model.dns.servers.length + 1), type: 'udp', server: '' })
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
.modal-wide { max-width: 760px; width: 94vw; }

.tabs { display: flex; gap: 0.25rem; border-bottom: 1px solid var(--paper-border); margin-bottom: 1rem; }
.tab {
  background: none; border: none; padding: 0.5rem 0.9rem; font-size: 0.82rem;
  color: var(--ink-secondary); border-bottom: 2px solid transparent; cursor: pointer;
}
.tab.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }

.form-body { max-height: 56vh; overflow-y: auto; padding-right: 0.25rem; }
.section-block { border: 1px solid var(--paper-border); border-radius: var(--radius-sm); padding: 0.9rem; margin-bottom: 1rem; }
.section-block h4 { font-size: 0.8rem; font-weight: 650; color: var(--ink-primary); margin: 0 0 0.6rem; }
.row-card { border: 1px dashed var(--paper-border); border-radius: var(--radius-sm); padding: 0.6rem; margin-bottom: 0.5rem; }
.row-grid { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
.row-grid > input, .row-grid > select { flex: 1; min-width: 90px; }
.row-grid-tun { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; margin-top: 0.5rem; }
.row-grid-tun > input, .row-grid-tun > select { flex: 1; min-width: 110px; }
.chk { display: flex; align-items: center; gap: 0.35rem; font-size: 0.78rem; color: var(--ink-secondary); white-space: nowrap; }
.chk input { width: auto; }

.json-editor {
  width: 100%; min-height: 360px; resize: vertical;
  font-family: var(--font-mono); font-size: 0.74rem; line-height: 1.55;
  background: var(--paper-bg); border: 1px solid var(--paper-border);
  border-radius: var(--radius-sm); padding: 0.75rem; color: var(--ink-primary);
}
.json-err { color: var(--bad); }
</style>
