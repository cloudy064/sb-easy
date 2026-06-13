<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>Subscriptions</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">Import proxy nodes from subscription URLs. Supports Clash YAML and base64-encoded proxy URI lists.</p>
      </div>
      <button class="btn-primary" @click="showAdd = true">Add Subscription</button>
    </div>

    <div v-if="store.loading" class="loading-center"><div class="spinner"></div></div>
    <div v-else-if="store.subs.length === 0" class="empty-state">
      <span class="empty-icon">&infin;</span>
      <p>No subscriptions configured. Add a subscription URL to automatically import and update proxy nodes.</p>
    </div>

    <div v-else class="section-stack">
      <article v-for="sub in store.subs" :key="sub.id" class="card sub-card">
        <div class="sub-main">
          <div class="sub-info">
            <h3 class="sub-name">{{ sub.name }}</h3>
            <div class="sub-url text-xs font-mono text-muted truncate">{{ sub.url }}</div>
            <div class="sub-meta">
              <span>Refresh every {{ sub.refresh_interval }}s</span>
              <span class="sub-sep">·</span>
              <span>Last fetched: <strong>{{ sub.last_fetched_at || 'Never' }}</strong></span>
            </div>
          </div>
          <div class="sub-actions">
            <button
              class="btn-primary btn-sm"
              @click="fetchSub(sub.id)"
              :disabled="fetchingId === sub.id"
            >
              <span v-if="fetchingId === sub.id" class="spinner" style="width:14px;height:14px;border-width:1.5px"></span>
              <span v-else>Fetch Now</span>
            </button>
            <button class="btn-danger btn-sm" @click="confirmDelete(sub)">Delete</button>
          </div>
        </div>

        <!-- Last result preview -->
        <div v-if="sub.last_fetch_result" class="sub-result">
          <div class="sub-result-title">Last Import</div>
          <div class="text-xs text-muted">{{ parseResult(sub.last_fetch_result) }}</div>
        </div>
      </article>
    </div>

    <!-- Fetch Result -->
    <div v-if="fetchResult" class="modal-overlay" @click.self="fetchResult = null">
      <div class="modal">
        <h3>Import Complete</h3>
        <div class="result-grid">
          <div class="result-item">
            <span class="result-num" style="color:var(--ok)">{{ fetchResult.added }}</span>
            <span class="result-label">Added</span>
          </div>
          <div class="result-item">
            <span class="result-num" style="color:var(--info)">{{ fetchResult.updated }}</span>
            <span class="result-label">Updated</span>
          </div>
          <div class="result-item">
            <span class="result-num" style="color:var(--ink-muted)">{{ fetchResult.skipped }}</span>
            <span class="result-label">Skipped</span>
          </div>
        </div>
        <div v-if="fetchResult.errors.length" class="result-errors">
          <div v-for="(e, i) in fetchResult.errors" :key="i" class="text-xs" style="color:var(--bad)">{{ e }}</div>
        </div>
        <div class="modal-actions">
          <button class="btn-primary" @click="fetchResult = null">Done</button>
        </div>
      </div>
    </div>

    <!-- Add Dialog -->
    <div v-if="showAdd" class="modal-overlay" @click.self="showAdd = false">
      <div class="modal">
        <h3>Add Subscription</h3>
        <form @submit.prevent="doAdd">
          <div class="form-group"><label>Name</label><input v-model="addForm.name" required placeholder="e.g. My Provider" /></div>
          <div class="form-group"><label>Subscription URL</label><input v-model="addForm.url" required placeholder="https://subscribe.example.com/api/..." /></div>
          <div class="form-group"><label>Auto-refresh interval (seconds)</label><input v-model.number="addForm.refresh_interval" type="number" placeholder="3600" /></div>
          <p class="text-xs text-muted mb-3">Supports base64-encoded proxy URI lists and Clash YAML proxies.</p>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showAdd = false">Cancel</button>
            <button type="submit" class="btn-primary">Add & Fetch</button>
          </div>
        </form>
      </div>
    </div>

    <!-- Delete -->
    <div v-if="deleteTarget" class="modal-overlay" @click.self="deleteTarget = null">
      <div class="modal">
        <h3>Remove &ldquo;{{ deleteTarget.name }}&rdquo;?</h3>
        <p class="text-sm text-muted">The subscription will be removed, but any nodes already imported from it will be kept.</p>
        <div class="modal-actions">
          <button class="btn-secondary" @click="deleteTarget = null">Cancel</button>
          <button class="btn-danger" @click="doDelete">Remove</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useSubscriptionsStore } from '../stores/subscriptions'
import type { Subscription, FetchResult } from '../types'

const store = useSubscriptionsStore()
const showAdd = ref(false)
const deleteTarget = ref<Subscription | null>(null)
const fetchingId = ref<string | null>(null)
const fetchResult = ref<FetchResult | null>(null)
const addForm = ref({ name: '', url: '', refresh_interval: 3600 })

onMounted(() => store.fetchAll())

function parseResult(raw: string) {
  try {
    const r = JSON.parse(raw)
    return `Added ${r.added}, updated ${r.updated}, skipped ${r.skipped} of ${r.total} total nodes.`
  } catch { return raw }
}

async function doAdd() {
  const sub = await store.create(addForm.value)
  showAdd.value = false
  addForm.value = { name: '', url: '', refresh_interval: 3600 }
  // Auto-fetch
  fetchingId.value = sub.id
  try { fetchResult.value = await store.fetchOne(sub.id) } catch {}
  fetchingId.value = null
}

function confirmDelete(sub: Subscription) { deleteTarget.value = sub }
async function doDelete() {
  if (!deleteTarget.value) return
  await store.remove(deleteTarget.value.id)
  deleteTarget.value = null
}

async function fetchSub(id: string) {
  fetchingId.value = id
  try { fetchResult.value = await store.fetchOne(id) } catch {}
  fetchingId.value = null
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
