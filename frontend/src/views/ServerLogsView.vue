<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.serverlogs.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.serverlogs.desc') }}</p>
      </div>
      <div class="flex-center gap-3">
        <label class="chk text-sm"><input type="checkbox" v-model="autoscroll" /> auto-scroll</label>
        <span class="text-xs text-muted">{{ lines.length }} lines</span>
      </div>
    </div>

    <div class="card">
      <div class="log-box" ref="box">
        <div v-for="(l, i) in lines" :key="i" class="log-line">{{ l }}</div>
        <p v-if="!lines.length" class="text-sm text-muted">No server logs yet.</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { useI18n } from '../composables/i18n'
import client from '../api/client'

const { t } = useI18n()
const lines = ref<string[]>([])
const autoscroll = ref(true)
const box = ref<HTMLElement | null>(null)
let timer: ReturnType<typeof setInterval> | null = null

async function load() {
  try {
    const { data } = await client.get('/system/logs')
    lines.value = Array.isArray(data?.lines) ? data.lines : []
    if (autoscroll.value) {
      await nextTick()
      if (box.value) box.value.scrollTop = box.value.scrollHeight
    }
  } catch { /* keep last */ }
}

onMounted(() => { load(); timer = setInterval(load, 3000) })
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
</script>

<style scoped>
.chk { display: flex; align-items: center; gap: 0.4rem; color: var(--ink-secondary); }
.card { padding: 1rem 1.25rem; }
.log-box { height: 70vh; min-height: 360px; overflow-y: auto; background: #1c1a17; border-radius: var(--radius-sm); padding: 0.85rem 1.1rem; font-family: var(--font-mono); font-size: 0.73rem; line-height: 1.65; }
.log-line { color: #d8d0c4; white-space: pre-wrap; word-break: break-all; }
</style>
