<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import AppIcon from './AppIcon.vue'

type Choice = { key: string; tag: string; label?: string; type: string; mode: 'node' | 'server' | 'default' }
const props = defineProps<{ id: string; current?: string; mode: 'node' | 'server' | 'default'; server: string; defaultExit?: string; allowDefault: boolean; editable: boolean; disabled?: boolean; loading?: boolean; nodes: { tag: string; type: string; label?: string; source?: string }[] }>()
const emit = defineEmits<{ select: [mode: 'node' | 'server' | 'default', node?: string] }>()
const trigger = ref<HTMLButtonElement>()
const popup = ref<HTMLElement>()
const input = ref<HTMLInputElement>()
const open = ref(false)
const query = ref('')
const active = ref(0)
const position = ref({ left: '0px', top: '0px', width: '320px', maxHeight: '360px' })
const sourceLabel = computed(() => props.mode === 'server' ? '跟随服务器' : props.mode === 'default' ? '跟随默认代理' : '本机指定节点')
const choices = computed<Choice[]>(() => [
  { key: 'server', tag: '跟随服务器', type: props.server || '由服务器决定', mode: 'server' },
  ...(props.editable && props.allowDefault ? [{ key: 'default', tag: '跟随默认代理', type: props.defaultExit || '与默认代理保持一致', mode: 'default' as const }] : []),
  ...(props.editable ? props.nodes.map(n => ({ key: `node:${n.tag}`, tag: n.tag, label: n.label, type: `${n.type.toUpperCase()}${n.source ? ' · ' + n.source : ''}`, mode: 'node' as const })) : []),
])
const filtered = computed(() => choices.value.filter(n => `${n.tag} ${n.type}`.toLowerCase().includes(query.value.trim().toLowerCase())))
function selected(choice: Choice) { return choice.mode === props.mode && (choice.mode !== 'node' || choice.tag === props.current) }
const activeId = computed(() => filtered.value.length ? `${props.id}-option-${active.value}` : undefined)
function place() {
  const r = trigger.value?.getBoundingClientRect()
  if (!r) return
  const below = window.innerHeight - r.bottom - 16
  const above = r.top - 16
  const height = Math.min(360, Math.max(below, above))
  position.value = { left: `${Math.max(8, Math.min(r.left, window.innerWidth - r.width - 8))}px`, width: `${r.width}px`, top: `${below >= Math.min(360, above) ? r.bottom + 8 : r.top - height - 8}px`, maxHeight: `${height}px` }
}
async function show() {
  if (props.disabled) return
  open.value = true
  query.value = ''
  await nextTick()
  active.value = 0
  place()
  await nextTick()
  input.value?.focus()
  reveal()
}
function close(focus = false) { open.value = false; if (focus) trigger.value?.focus() }
function choose(choice: Choice) { if (props.disabled) return; close(true); if (!selected(choice)) emit('select', choice.mode, choice.mode === 'node' ? choice.tag : undefined) }
function reveal() { document.getElementById(activeId.value || '')?.scrollIntoView({ block: 'nearest' }) }
async function key(event: KeyboardEvent) {
  if (event.key === 'Escape') { event.preventDefault(); close(true) }
  if (event.key === 'Tab') close(true)
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault()
    active.value = Math.max(0, Math.min(filtered.value.length - 1, active.value + (event.key === 'ArrowDown' ? 1 : -1)))
    await nextTick(); reveal()
  }
  if (event.key === 'Enter' && filtered.value[active.value]) { event.preventDefault(); choose(filtered.value[active.value]) }
}
function outside(event: PointerEvent) {
  if (!popup.value?.contains(event.target as Node) && !trigger.value?.contains(event.target as Node)) close()
}
watch(query, () => { active.value = 0 })
watch(open, value => {
  if (value) { document.addEventListener('pointerdown', outside); window.addEventListener('resize', place); window.addEventListener('scroll', place, true) }
  else cleanup()
})
function cleanup() { document.removeEventListener('pointerdown', outside); window.removeEventListener('resize', place); window.removeEventListener('scroll', place, true) }
onBeforeUnmount(cleanup)
</script>

<template>
  <button :id="id" ref="trigger" type="button" class="node-picker-trigger" :class="{ expanded: open }" :disabled="disabled" aria-haspopup="listbox" :aria-expanded="open" :aria-controls="open ? `${id}-list` : undefined" @click="open ? close() : show()" @keydown.down.prevent="show()" @keydown.up.prevent="show()">
    <span class="picker-symbol"><AppIcon name="proxies" /></span>
    <span class="picker-value"><small>{{ loading ? '正在切换…' : sourceLabel }}</small><strong>{{ nodes.find(node => node.tag === current)?.label || current || '选择出口' }}</strong></span>
    <svg class="picker-chevron" viewBox="0 0 24 24"><path d="m7 10 5 5 5-5" /></svg>
  </button>
  <Teleport to="body">
    <div v-if="open" ref="popup" class="node-picker-popup" :style="position" @keydown="key">
      <div class="picker-search"><AppIcon name="search" /><input ref="input" v-model="query" role="combobox" aria-label="搜索节点或协议" aria-autocomplete="list" aria-expanded="true" :aria-controls="`${id}-list`" :aria-activedescendant="activeId" placeholder="搜索节点或协议…" /></div>
      <div class="picker-list-heading"><span>可用出口</span><span>{{ filtered.length }} 个</span></div>
      <div :id="`${id}-list`" role="listbox" aria-label="本机出口节点" class="picker-options">
        <div v-for="(node, index) in filtered" :id="`${id}-option-${index}`" :key="node.key" role="option" :aria-selected="selected(node)" class="picker-option" :aria-disabled="disabled" :class="{ inherited: node.mode !== 'node', highlighted: index === active, selected: selected(node) }" @pointermove="active = index" @mousedown.prevent @click="choose(node)">
          <span class="picker-option-copy"><strong>{{ node.label || node.tag }}</strong><small>{{ node.type }}<span v-if="node.mode === 'node' && node.tag === current" class="picker-current">当前出口</span></small></span><AppIcon v-if="selected(node)" name="check" />
        </div>
        <div v-if="!filtered.length" class="picker-empty">没有匹配的节点<small>试试地区名称或协议</small></div>
      </div>
      <div class="picker-hint">选中即保存 · ↑ ↓ 选择 · Esc 收起</div>
    </div>
  </Teleport>
</template>

<style>
.node-picker-trigger { width:100%; display:flex; align-items:center; gap:12px; padding:13px 14px; border:1px solid var(--border); border-radius:12px; background:var(--surface); color:var(--ink); text-align:left; min-width:0; }
.node-picker-trigger:hover:not(:disabled), .node-picker-trigger.expanded { border-color:var(--accent); background:var(--accent-bg); }
.picker-symbol { display:grid; place-items:center; width:34px; height:34px; flex:none; border-radius:9px; background:var(--accent-bg); color:var(--accent); }
.picker-value { flex:1; min-width:0; }.picker-value small { display:block; color:var(--secondary); font-size:11px; margin-bottom:4px; }.picker-value strong { display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:13px; font-weight:550; }
.picker-chevron { width:18px; height:18px; flex:none; color:var(--muted); transition:transform .16s; }.expanded .picker-chevron { transform:rotate(180deg); }
.node-picker-popup { position:fixed; z-index:1000; display:flex; flex-direction:column; padding:8px; border:1px solid var(--border); border-radius:15px; background:var(--surface); color:var(--ink); box-shadow:0 14px 44px #0002,0 3px 10px #0001; }
.picker-search { display:flex; align-items:center; gap:9px; margin:2px 2px 6px; padding:9px 10px; border:1px solid var(--border); background:var(--paper); border-radius:8px; color:var(--muted); }.picker-search:focus-within { border-color:var(--accent); }.picker-search svg { width:16px; height:16px; flex:none; }.picker-search input { border:0; outline:0; background:transparent; color:var(--ink); width:100%; min-width:0; padding:0; font-size:13px; }
.picker-list-heading { display:flex; justify-content:space-between; padding:7px 10px; color:var(--muted); font-size:10px; letter-spacing:.04em; }
.picker-options { overflow-y:auto; overscroll-behavior:contain; min-height:0; scrollbar-width:thin; }.picker-option { display:flex; align-items:center; gap:10px; padding:10px 12px; border-radius:8px; cursor:pointer; margin:2px 0; }.picker-option.highlighted { background:var(--paper); }.picker-option.selected { background:var(--accent-bg); color:var(--accent); }.picker-option>svg { flex:none; width:17px; height:17px; }.picker-option-copy { flex:1; min-width:0; }.picker-option-copy strong { display:block; font-size:13px; font-weight:550; overflow-wrap:anywhere; line-height:1.5; }.picker-option-copy small { display:flex; gap:10px; align-items:center; margin-top:3px; font-size:10px; color:var(--muted); }.picker-current { color:var(--accent); }.picker-current::before { content:'●'; font-size:7px; margin-right:4px; }.picker-hint { padding:10px 10px 3px; border-top:1px solid var(--border); margin-top:6px; color:var(--muted); font-size:10px; }.picker-empty { padding:24px 10px; text-align:center; font-size:13px; }.picker-empty small { display:block; color:var(--muted); margin-top:6px; }
</style>
