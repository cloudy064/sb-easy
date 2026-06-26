<template>
  <div class="host-select" v-if="hosts.length > 1">
    <span class="host-select-label">{{ t('hosts.target') }}</span>
    <NmSelect v-model="selectedHost" :options="hostOptions" @change="onChange" width="200px" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useI18n } from '../composables/i18n'
import { useHostTarget } from '../composables/hostTarget'

const { t } = useI18n()
const { hosts, selectedHost, fetchHosts } = useHostTarget()

const hostOptions = computed(() => hosts.value.map(h => ({
  value: h.id,
  label: h.capabilities.is_self ? t('hosts.target.local') : h.name,
})))

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
</style>
