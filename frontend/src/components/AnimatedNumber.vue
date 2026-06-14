<template><span>{{ text }}</span></template>

<script setup lang="ts">
import { ref, computed, watch, onBeforeUnmount } from 'vue'

// Eases a displayed value toward `value` with requestAnimationFrame so 1 Hz
// updates read as a smooth count instead of a hard jump. The rAF loop only
// runs while there is a gap to close, so idle numbers cost nothing.
const props = defineProps<{
  value: number
  format: (n: number) => string
  ease?: number
}>()

// Always work with a numeric target; a string prop would turn `+=` into string
// concatenation and produce garbage values.
const target = computed(() => {
  const n = Number(props.value)
  return Number.isFinite(n) ? n : 0
})

const display = ref(target.value)
let raf = 0

function loop() {
  const diff = target.value - display.value
  if (Math.abs(diff) < 0.5) {
    display.value = target.value
    raf = 0
    return
  }
  display.value += diff * (props.ease ?? 0.14)
  raf = requestAnimationFrame(loop)
}

watch(target, () => {
  if (!raf) raf = requestAnimationFrame(loop)
})

onBeforeUnmount(() => raf && cancelAnimationFrame(raf))

const text = computed(() => props.format(Math.max(0, display.value)))
</script>
