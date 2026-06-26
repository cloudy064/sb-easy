<template>
  <div class="nm-select" :style="{ width: width || '100%' }" ref="rootRef">
    <button
      class="nm-select-trigger"
      :class="{ 'nm-select-open': open, 'text-sm': small }"
      @click="toggle"
      @blur="onBlur"
      type="button"
    >
      <span class="nm-select-text">{{ selectedLabel || placeholder }}</span>
      <svg class="nm-select-chevron" :class="{ open }" width="12" height="12" viewBox="0 0 12 12">
        <path d="M3 5l3 3 3-3" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </button>
    <Transition name="nm-drop">
      <div v-if="open" class="nm-select-dropdown">
        <button
          v-for="opt in options"
          :key="opt.value"
          class="nm-select-option"
          :class="{ active: opt.value === modelValue }"
          @mousedown.prevent="select(opt.value)"
          type="button"
        >
          {{ opt.label }}
        </button>
      </div>
    </Transition>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick } from 'vue'

interface Option {
  value: string
  label: string
}

const props = withDefaults(defineProps<{
  modelValue: string
  options: Option[]
  placeholder?: string
  width?: string
  small?: boolean
}>(), {
  placeholder: '',
})

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
  (e: 'change', value: string): void
}>()

const open = ref(false)
const rootRef = ref<HTMLElement | null>(null)

const selectedLabel = computed(() => {
  const opt = props.options.find(o => o.value === props.modelValue)
  return opt?.label ?? ''
})

function toggle() {
  open.value = !open.value
}

function select(value: string) {
  emit('update:modelValue', value)
  emit('change', value)
  open.value = false
}

function onBlur(e: FocusEvent) {
  nextTick(() => {
    if (rootRef.value && !rootRef.value.contains(document.activeElement)) {
      open.value = false
    }
  })
}

function onClickOutside(e: MouseEvent) {
  if (rootRef.value && !rootRef.value.contains(e.target as Node)) {
    open.value = false
  }
}

onMounted(() => document.addEventListener('click', onClickOutside))
onUnmounted(() => document.removeEventListener('click', onClickOutside))
</script>

<style scoped>
.nm-select {
  position: relative;
  display: inline-block;
}

.nm-select-trigger {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  padding: 0.65rem 0.9rem;
  font-family: var(--font);
  font-size: 0.88rem;
  border: none;
  border-radius: var(--radius-sm);
  background: var(--paper-bg);
  color: var(--ink-primary);
  box-shadow: var(--nm-shadow-sm-in);
  cursor: pointer;
  transition: box-shadow 0.2s;
  text-align: left;
  font-weight: 500;
}
.nm-select-trigger.text-sm { font-size: 0.83rem; }
.nm-select-trigger:hover {
  box-shadow: inset 4px 4px 8px var(--nm-dark), inset -4px -4px 8px var(--nm-light);
}
.nm-select-trigger.nm-select-open {
  box-shadow: inset 3px 3px 6px var(--nm-dark), inset -3px -3px 6px var(--nm-light);
}

.nm-select-text {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.nm-select-chevron {
  flex-shrink: 0;
  opacity: 0.4;
  color: var(--ink-secondary);
  transition: transform 0.2s;
}
.nm-select-chevron.open { transform: rotate(180deg); }

.nm-select-dropdown {
  position: absolute;
  top: calc(100% + 8px);
  left: 0;
  right: 0;
  z-index: 500;
  background: var(--nm-card-bg);
  border: none;
  border-radius: var(--radius);
  box-shadow:
    6px 6px 16px var(--nm-dark),
    -6px -6px 16px var(--nm-light),
    0 8px 24px rgba(0,0,0,.08);
  padding: 0.5rem;
  max-height: 260px;
  overflow-y: auto;
}

.nm-select-option {
  width: 100%;
  display: block;
  padding: 0.55rem 0.8rem;
  border: none;
  border-radius: calc(var(--radius) - 4px);
  background: transparent;
  color: var(--ink-secondary);
  font-size: 0.85rem;
  text-align: left;
  cursor: pointer;
  transition: all 0.15s;
  font-weight: 500;
}
.nm-select-option:hover {
  background: var(--paper-bg);
  color: var(--ink-primary);
}
.nm-select-option.active {
  background: var(--accent-subtle);
  color: var(--accent);
  font-weight: 600;
  box-shadow: var(--nm-shadow-sm-in);
}

/* Transition */
.nm-drop-enter-active { animation: nmDropIn 0.18s ease; }
.nm-drop-leave-active { animation: nmDropIn 0.12s ease reverse; }
@keyframes nmDropIn {
  from { opacity: 0; transform: translateY(-6px); }
  to   { opacity: 1; transform: translateY(0); }
}
</style>
