<template>
  <div class="host-select" v-if="hosts.length > 1">
    <span class="host-select-label">{{ t('hosts.target') }}</span>
    <select v-model="selectedHost" @change="onChange">
      <option v-for="h in hosts" :key="h.id" :value="h.id">
        {{ h.capabilities.is_self ? t('hosts.target.local') : h.name }}
      </option>
    </select>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useI18n } from '../composables/i18n'
import { useHostTarget } from '../composables/hostTarget'

const { t } = useI18n()
const { hosts, selectedHost, fetchHosts } = useHostTarget()

const emit = defineEmits<{ (e: 'change', host: string): void }>()
function onChange() {
  emit('change', selectedHost.value)
}

onMounted(fetchHosts)
</script>

<style scoped>
.host-select { display: flex; align-items: center; gap: 0.5rem; }
.host-select-label {
  font-size: 0.7rem; font-weight: 600; color: var(--ink-muted);
  text-transform: uppercase; letter-spacing: 0.04em;
}
.host-select select { max-width: 200px; font-size: 0.82rem; padding: 0.3rem 0.5rem; }
</style>
