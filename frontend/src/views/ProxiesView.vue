<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.proxies.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.proxies.desc') }}</p>
      </div>
      <div class="flex-center gap-3">
        <HostSelect @change="load" />
        <button class="btn-secondary btn-sm" @click="load">Refresh</button>
      </div>
    </div>

    <div v-if="loading" class="loading-center"><div class="spinner"></div></div>

    <div v-else-if="error" class="empty-state">
      <span class="empty-icon">!</span>
      <p>{{ error }}</p>
      <p class="text-xs" style="margin-top:0.5rem">Check the sing-box Clash API URL in Settings and that <code>experimental.clash_api</code> is enabled.</p>
    </div>

    <div v-else-if="groups.length === 0" class="empty-state">
      <span class="empty-icon">·</span>
      <p>No selectable proxy groups reported by sing-box.</p>
    </div>

    <div v-else class="section-stack">
      <div v-for="g in groups" :key="g.name" class="card">
        <div class="flex-between mb-4">
          <div class="flex-center gap-3">
            <h3 class="section-title" style="margin:0">{{ g.name }}</h3>
            <span class="badge badge-gray">{{ g.type }}</span>
            <span class="text-xs text-muted">{{ g.all.length }} nodes</span>
          </div>
          <button class="btn-secondary btn-sm" @click="testGroup(g.name)" :disabled="testing[g.name]">
            {{ testing[g.name] ? 'Testing…' : 'Test group' }}
          </button>
        </div>
        <div class="proxy-grid">
          <button
            v-for="node in g.all"
            :key="node"
            class="proxy-chip"
            :class="{ active: g.now === node }"
            :disabled="!g.selectable || switching"
            @click="select(g, node)"
          >
            <span class="proxy-chip-name truncate">{{ node }}</span>
            <span class="proxy-chip-delay" :class="delayClass(delays[node])">
              {{ delays[node] != null ? delays[node] + 'ms' : '—' }}
            </span>
          </button>
        </div>
      </div>
    </div>

    <div v-if="toast" class="toast"><div class="toast-item" :class="toastClass">{{ toast }}</div></div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
const { t } = useI18n()
import { ref, reactive, onMounted } from 'vue'
import client from '../api/client'
import HostSelect from '../components/HostSelect.vue'
import { useHostTarget } from '../composables/hostTarget'
import type { ProxyGroup } from '../types'

const { reqParams } = useHostTarget()

const loading = ref(true)
const switching = ref(false)
const error = ref('')
const groups = ref<ProxyGroup[]>([])
const delays = reactive<Record<string, number | null>>({})
const testing = reactive<Record<string, boolean>>({})
const toast = ref('')
const toastClass = ref('toast-success')

const GROUP_TYPES = new Set(['Selector', 'URLTest', 'Fallback', 'LoadBalance'])

function notify(msg: string, ok = true) {
  toast.value = msg
  toastClass.value = ok ? 'toast-success' : 'toast-error'
  setTimeout(() => (toast.value = ''), 2200)
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const { data } = await client.get('/sing-box/proxies', { params: reqParams.value })
    const all = data.proxies || {}
    const result: ProxyGroup[] = []
    for (const name of Object.keys(all)) {
      const p = all[name]
      if (GROUP_TYPES.has(p.type) && Array.isArray(p.all)) {
        result.push({
          name,
          type: p.type,
          now: p.now ?? '',
          all: p.all,
          selectable: p.type === 'Selector',
        })
      }
    }
    // collect node delays from history
    for (const name of Object.keys(all)) {
      const h = all[name].history
      if (Array.isArray(h) && h.length) delays[name] = h[h.length - 1].delay || null
    }
    groups.value = result
  } catch (e: any) {
    error.value = 'Could not reach the sing-box Clash API.'
  } finally {
    loading.value = false
  }
}

async function select(group: ProxyGroup, node: string) {
  if (!group.selectable || group.now === node) return
  switching.value = true
  try {
    await client.put(`/sing-box/proxies/${encodeURIComponent(group.name)}`, { name: node }, { params: reqParams.value })
    group.now = node
    notify(`${group.name} → ${node}`)
  } catch {
    notify('Failed to switch node', false)
  } finally {
    switching.value = false
  }
}

async function testGroup(name: string) {
  testing[name] = true
  try {
    const { data } = await client.get(`/sing-box/group/${encodeURIComponent(name)}/delay`, {
      params: { url: 'https://www.gstatic.com/generate_204', timeout: 5000, ...reqParams.value },
    })
    for (const node of Object.keys(data || {})) delays[node] = data[node]
    notify(`Tested ${name}`)
  } catch {
    notify('Group test failed', false)
  } finally {
    testing[name] = false
  }
}

function delayClass(ms: number | null | undefined) {
  if (ms == null) return 'text-muted'
  if (ms < 200) return 'delay-good'
  if (ms < 500) return 'delay-ok'
  return 'delay-slow'
}

onMounted(load)
</script>

<style scoped>
.section-title { font-size: 0.95rem; font-weight: 650; }
.proxy-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
  gap: 0.6rem;
}
.proxy-chip {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;
  padding: 0.55rem 0.75rem;
  background: var(--paper-bg);
  border: 1px solid var(--paper-border);
  border-radius: var(--radius-sm);
  font-size: 0.8rem;
  color: var(--ink-secondary);
  text-align: left;
  transition: all 0.15s;
}
.proxy-chip:hover:not(:disabled) { border-color: var(--accent-dim); }
.proxy-chip.active {
  border-color: var(--accent);
  background: var(--accent-subtle);
  color: var(--accent);
  font-weight: 600;
}
.proxy-chip:disabled { cursor: default; }
.proxy-chip-name { min-width: 0; }
.proxy-chip-delay { font-family: var(--font-mono); font-size: 0.7rem; flex-shrink: 0; }
.delay-good { color: var(--ok); }
.delay-ok { color: var(--warn); }
.delay-slow { color: var(--bad); }
</style>
