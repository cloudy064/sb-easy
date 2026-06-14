<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.config.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.config.desc') }}</p>
      </div>
      <div class="flex-center gap-3">
        <select v-model="view" class="text-sm" style="max-width:160px">
          <option value="full">Full config</option>
          <option value="outbounds">Outbounds only</option>
        </select>
        <button class="btn-secondary btn-sm" @click="copy">{{ copied ? 'Copied' : 'Copy' }}</button>
        <button class="btn-primary btn-sm" @click="download">Download</button>
      </div>
    </div>

    <div v-if="loading" class="loading-center"><div class="spinner"></div></div>
    <div v-else class="card config-card">
      <div class="config-meta text-xs text-muted mb-3">
        {{ outboundCount }} outbound(s) · {{ bytes }} bytes
      </div>
      <pre class="config-pre">{{ pretty }}</pre>
    </div>

    <div v-if="toast" class="toast"><div class="toast-item toast-success">{{ toast }}</div></div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
const { t } = useI18n()
import { ref, computed, watch, onMounted } from 'vue'
import client from '../api/client'

const view = ref<'full' | 'outbounds'>('full')
const data = ref<any>(null)
const loading = ref(true)
const copied = ref(false)
const toast = ref('')

const pretty = computed(() => (data.value ? JSON.stringify(data.value, null, 2) : ''))
const bytes = computed(() => new Blob([pretty.value]).size)
const outboundCount = computed(() => {
  if (!data.value) return 0
  const arr = Array.isArray(data.value) ? data.value : data.value.outbounds || []
  return arr.length
})

async function load() {
  loading.value = true
  try {
    const path = view.value === 'full' ? '/config/sing-box/full' : '/config/sing-box/outbounds'
    const { data: d } = await client.get(path)
    data.value = d
  } finally {
    loading.value = false
  }
}

async function copy() {
  await navigator.clipboard.writeText(pretty.value)
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}

function download() {
  const blob = new Blob([pretty.value], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = view.value === 'full' ? 'config.json' : 'outbounds.json'
  a.click()
  URL.revokeObjectURL(url)
  toast.value = 'Downloaded'
  setTimeout(() => (toast.value = ''), 1800)
}

watch(view, load)
onMounted(load)
</script>

<style scoped>
.config-card { padding: 1.25rem 1.5rem; }
.config-pre {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  line-height: 1.6;
  background: #1c1a17;
  color: #d8d0c4;
  padding: 1rem 1.25rem;
  border-radius: var(--radius-sm);
  overflow-x: auto;
  max-height: 70vh;
  overflow-y: auto;
  white-space: pre;
}
</style>
