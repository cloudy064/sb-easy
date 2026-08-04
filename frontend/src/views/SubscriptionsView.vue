<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.subscriptions.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.subscriptions.desc') }}</p>
      </div>
      <button class="btn-primary" @click="showAdd = true">{{ t('subs.add') }}</button>
    </div>

    <div v-if="store.loading" class="loading-center"><div class="spinner"></div></div>
    <div v-else-if="store.subs.length === 0" class="empty-state">
      <span class="empty-icon">&infin;</span>
      <p>{{ t('subs.empty') }}</p>
    </div>

    <div v-else class="section-stack">
      <article v-for="sub in store.subs" :key="sub.id" class="card sub-card">
        <div class="sub-main">
          <div class="sub-info">
            <h3 class="sub-name">{{ sub.name }}</h3>
            <div class="sub-url text-xs font-mono text-muted truncate">{{ sub.url }}</div>
            <div class="sub-meta">
              <span>{{ t('subs.refreshEvery') }} {{ sub.refresh_interval }}{{ t('subs.seconds') }}</span>
              <span class="sub-sep">·</span>
              <span>{{ t('subs.lastFetched') }}: <strong>{{ sub.last_fetched_at ? formatTime(sub.last_fetched_at) : t('subs.never') }}</strong></span>
            </div>
          </div>
          <div class="sub-actions">
            <button
              class="btn-primary btn-sm"
              @click="fetchSub(sub.id)"
              :disabled="fetchingId === sub.id"
            >
              <span v-if="fetchingId === sub.id" class="spinner" style="width:14px;height:14px;border-width:1.5px"></span>
              <span v-else>{{ t('subs.fetchNow') }}</span>
            </button>
            <button class="btn-danger btn-sm" @click="confirmDelete(sub)">{{ t('subs.delete') }}</button>
          </div>
        </div>

        <!-- Last result preview -->
        <div v-if="sub.last_fetch_result" class="sub-result">
          <div class="sub-result-title">{{ t('subs.lastImport') }}</div>
          <div class="text-xs text-muted">{{ parseResult(sub.last_fetch_result) }}</div>
        </div>
      </article>
    </div>

    <!-- Fetch Result / Error -->
    <div v-if="fetchResult || fetchError" class="modal-overlay" @click.self="closeResult">
      <div class="modal">
        <!-- Error: network / HTTP / parse failure -->
        <template v-if="fetchError">
          <h3 style="color:var(--bad)">{{ t('subs.result.errorTitle') }}</h3>
          <p class="text-sm" style="color:var(--bad); word-break:break-word">{{ fetchError }}</p>
          <div class="modal-actions"><button class="btn-primary" @click="closeResult">{{ t('subs.result.done') }}</button></div>
        </template>
        <!-- Zero nodes: reached the URL but parsed nothing (bad format / empty) -->
        <template v-else-if="fetchResult && foundCount(fetchResult) === 0">
          <h3 style="color:var(--warn)">{{ t('subs.result.zeroTitle') }}</h3>
          <p class="text-sm text-muted">{{ t('subs.result.zeroHint') }}</p>
          <div v-if="fetchResult.errors.length" class="result-errors">
            <div v-for="(e, i) in fetchResult.errors" :key="i" class="text-xs" style="color:var(--bad)">{{ e }}</div>
          </div>
          <div class="modal-actions"><button class="btn-primary" @click="closeResult">{{ t('subs.result.done') }}</button></div>
        </template>
        <!-- Success -->
        <template v-else-if="fetchResult">
          <h3>{{ t('subs.result.title') }}</h3>
          <div class="result-grid">
            <div class="result-item">
              <span class="result-num" style="color:var(--ok)">{{ fetchResult.added }}</span>
              <span class="result-label">{{ t('subs.result.added') }}</span>
            </div>
            <div class="result-item">
              <span class="result-num" style="color:var(--info)">{{ fetchResult.updated }}</span>
              <span class="result-label">{{ t('subs.result.updated') }}</span>
            </div>
            <div class="result-item">
              <span class="result-num" style="color:var(--ink-muted)">{{ foundCount(fetchResult) }}</span>
              <span class="result-label">{{ t('subs.result.found') }}</span>
            </div>
          </div>
          <div v-if="fetchResult.errors.length" class="result-errors">
            <div v-for="(e, i) in fetchResult.errors" :key="i" class="text-xs" style="color:var(--bad)">{{ e }}</div>
          </div>
          <div class="modal-actions">
            <button class="btn-secondary" @click="closeResult">{{ t('subs.result.done') }}</button>
            <button class="btn-primary" @click="viewNodes">{{ t('subs.result.viewNodes') }}</button>
          </div>
        </template>
      </div>
    </div>

    <!-- Add Dialog -->
    <div v-if="showAdd" class="modal-overlay" @click.self="showAdd = false">
      <div class="modal">
        <h3>{{ t('subs.add') }}</h3>
        <form @submit.prevent="doAdd">
          <div class="form-group"><label>{{ t('subs.form.name') }}</label><input v-model="addForm.name" required :placeholder="t('subs.form.namePlaceholder')" /></div>
          <div class="form-group"><label>{{ t('subs.form.url') }}</label><input v-model="addForm.url" required :placeholder="t('subs.form.urlPlaceholder')" /></div>
          <div class="form-group"><label>{{ t('subs.form.interval') }}</label><input v-model.number="addForm.refresh_interval" type="number" placeholder="3600" /></div>
          <p class="text-xs text-muted mb-3">{{ t('subs.form.hint') }}</p>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showAdd = false">{{ t('subs.form.cancel') }}</button>
            <button type="submit" class="btn-primary">{{ t('subs.form.submit') }}</button>
          </div>
        </form>
      </div>
    </div>

    <!-- Delete -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal">
        <h3>{{ t('subs.delete.title') }} &ldquo;{{ deleteTarget.name }}&rdquo;?</h3>
        <p class="text-sm text-muted">{{ t('subs.delete.hint') }}</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="deleteTarget = null">{{ t('subs.form.cancel') }}</button>
          <button class="btn-danger" @click="doDelete">{{ t('subs.delete.confirm') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from '../composables/i18n'
import { useSubscriptionsStore } from '../stores/subscriptions'
import { useProxyNodesStore } from '../stores/proxyNodes'
import type { Subscription, FetchResult } from '../types'

const { t } = useI18n()
const router = useRouter()
const store = useSubscriptionsStore()
const proxyNodes = useProxyNodesStore()

const showAdd = ref(false)
const deleteTarget = ref<Subscription | null>(null)
const fetchingId = ref<string | null>(null)
const fetchResult = ref<FetchResult | null>(null)
const fetchError = ref<string | null>(null)
const addForm = ref({ name: '', url: '', refresh_interval: 3600 })

onMounted(() => store.fetchAll())

// `found` (total parsed) may be absent on older backends — fall back to add+update.
function foundCount(r: FetchResult): number {
  return r.found ?? r.added + r.updated
}

function parseResult(raw: string) {
  try {
    const r = JSON.parse(raw)
    const total = r.total ?? r.found ?? r.added + r.updated
    return `${r.added} ${t('subs.sum.added')} · ${r.updated} ${t('subs.sum.updated')} · ${total} ${t('subs.sum.found')}`
  } catch { return raw }
}

function formatTime(ts: string) {
  const d = new Date(ts)
  return isNaN(d.getTime()) ? ts : d.toLocaleString()
}

// Surface the backend error (AppError serializes as { error } ) instead of the
// old empty catch that made failures invisible.
function errMessage(e: any): string {
  return e?.response?.data?.error || e?.response?.data?.message || e?.message || String(e)
}

async function runFetch(id: string) {
  fetchingId.value = id
  fetchResult.value = null
  fetchError.value = null
  try {
    fetchResult.value = await store.fetchOne(id)
  } catch (e) {
    fetchError.value = errMessage(e)
    return
  } finally {
    fetchingId.value = null
  }
  // Refresh card metadata (last_fetched_at) + node list so a following
  // "View Nodes" is fresh. A refresh failure must NOT mask the successful
  // import that is already shown, so swallow it separately.
  Promise.all([store.fetchAll(), proxyNodes.fetchNodes()]).catch(() => {})
}

async function doAdd() {
  let sub: Subscription
  try {
    sub = await store.create(addForm.value)
  } catch (e) {
    fetchError.value = errMessage(e)
    return
  }
  showAdd.value = false
  addForm.value = { name: '', url: '', refresh_interval: 3600 }
  await runFetch(sub.id)
}

async function fetchSub(id: string) {
  await runFetch(id)
}

function closeResult() {
  fetchResult.value = null
  fetchError.value = null
}

function viewNodes() {
  closeResult()
  router.push('/proxies')
}

function confirmDelete(sub: Subscription) { deleteTarget.value = sub }
async function doDelete() {
  if (!deleteTarget.value) return
  try {
    await store.remove(deleteTarget.value.id)
  } catch (e) {
    fetchError.value = errMessage(e)
  }
  deleteTarget.value = null
}
</script>

<style scoped>
.sub-card {
  padding: 1.75rem;
}

.sub-main {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1.5rem;
  flex-wrap: wrap;
}

.sub-info { flex: 1; min-width: 0; }

.sub-name {
  font-size: 0.95rem;
  font-weight: 650;
  margin-bottom: 0.25rem;
}

.sub-url {
  max-width: 480px;
  word-break: break-all;
  margin-bottom: 0.4rem;
}

.sub-meta {
  font-size: 0.72rem;
  color: var(--ink-muted);
}
.sub-sep { margin: 0 0.4rem; }

.sub-actions {
  display: flex;
  gap: 0.4rem;
  flex-shrink: 0;
}

.sub-result {
  margin-top: 0.85rem;
  padding: 0.75rem 0.85rem;
  background: var(--paper-bg);
  border: 1px solid var(--paper-border);
  border-radius: var(--radius-sm);
}

.sub-result-title {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--ink-muted);
  margin-bottom: 0.25rem;
}

.result-grid {
  display: flex;
  gap: 2rem;
  justify-content: center;
  margin: 1rem 0;
}
.result-item {
  text-align: center;
}
.result-num {
  font-size: 2rem;
  font-weight: 680;
  display: block;
  line-height: 1;
}
.result-label {
  font-size: 0.72rem;
  color: var(--ink-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.result-errors {
  margin-top: 0.75rem;
  padding: 0.5rem;
  background: var(--bad-bg);
  border-radius: var(--radius-sm);
}
</style>
