<script setup lang="ts">
import { computed } from 'vue'
import NodePicker from './NodePicker.vue'
import type { RoutingGroup } from '../lib/protocol'
const props = defineProps<{ groups: RoutingGroup[]; nodes: { tag: string; type: string; label?: string; source?: string }[]; disabled: boolean; pending: string; live: boolean }>()
const emit = defineEmits<{ select: [group: string, mode: 'node' | 'server' | 'default', node?: string] }>()
const ordered = computed(() => [...props.groups].sort((a, b) => Number(b.id === 'default') - Number(a.id === 'default')))
const defaultExit = computed(() => props.groups.find(g => g.id === 'default')?.outbound)
</script>
<template>
  <section class="routing-home" aria-labelledby="routing-title">
    <div class="section-heading"><div><h2 id="routing-title">代理与服务分流</h2><p class="routing-subtitle">{{ live ? '选择出口，新连接立即生效。' : '选择会保存在本机，下次连接生效。' }} 本机设置会在同步和重启后保留。</p></div></div>
    <div class="routing-home-grid">
      <article v-for="group in ordered" :key="group.id" class="panel routing-home-card" :class="{ 'routing-default': group.id === 'default' }" :aria-busy="pending === group.id">
        <div class="routing-card-heading"><span class="routing-monogram">{{ group.id === 'default' ? '↗' : group.label.slice(0, 1) }}</span><div><h3>{{ group.label }}</h3><p>{{ group.id === 'default' ? '未单独分流的流量使用此出口' : '匹配此服务规则的流量使用此出口' }}</p></div><span v-if="group.mode !== 'server'" class="routing-local-badge">本机设置</span></div>
        <NodePicker :id="`routing-${group.id}`" :current="group.outbound" :mode="group.mode" :server="group.server_outbound" :default-exit="defaultExit" :allow-default="group.id !== 'default'" :allow-server="!group.local" :editable="group.editable" :nodes="nodes" :disabled="disabled || (!group.editable && group.mode === 'server')" :loading="pending === group.id" @select="(mode, node) => emit('select', group.id, mode, node)" />
        <p v-if="!group.editable" class="routing-reason">{{ group.reason }}</p>
      </article>
    </div>
  </section>
</template>
