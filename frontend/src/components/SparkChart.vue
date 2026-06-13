<template>
  <svg class="spark" viewBox="0 0 600 120" preserveAspectRatio="none">
    <path :d="area(downHist)" :fill="downColor" fill-opacity="0.10" stroke="none" />
    <path :d="line(downHist)" fill="none" :stroke="downColor" stroke-width="2"
          stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke" />
    <path :d="area(upHist)" :fill="upColor" fill-opacity="0.10" stroke="none" />
    <path :d="line(upHist)" fill="none" :stroke="upColor" stroke-width="2"
          stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke" />
  </svg>
</template>

<script setup lang="ts">
import { ref, watch, onMounted, onBeforeUnmount } from 'vue'

// A continuously scrolling sparkline. Samples arrive at ~1 Hz (each `seq` bump);
// a rAF loop slides the curve left between samples so the line flows in real
// time instead of stepping once per second. Self-contained so the parent's
// connection/log lists don't re-render every animation frame.
const props = defineProps<{
  down: number
  up: number
  seq: number
  downColor?: string
  upColor?: string
}>()

const W = 600
const H = 120
const MAX = 60
const STEP = W / (MAX - 1)
const INTERVAL = 1000 // expected ms between samples

const downHist = ref<number[]>([])
const upHist = ref<number[]>([])
const progress = ref(1)
let lastTick = 0
let raf = 0
let started = false

const downColor = props.downColor ?? 'var(--ok)'
const upColor = props.upColor ?? 'var(--info)'

function now() {
  return typeof performance !== 'undefined' ? performance.now() : Date.now()
}

function push() {
  downHist.value.push(props.down)
  upHist.value.push(props.up)
  if (downHist.value.length > MAX + 1) downHist.value.shift()
  if (upHist.value.length > MAX + 1) upHist.value.shift()
  lastTick = now()
  if (!started) { started = true; raf = requestAnimationFrame(frame) }
}

function frame() {
  progress.value = Math.min(1, (now() - lastTick) / INTERVAL)
  raf = requestAnimationFrame(frame)
}

watch(() => props.seq, push)
onMounted(() => { if (props.seq > 0) push() })
onBeforeUnmount(() => raf && cancelAnimationFrame(raf))

function peak(): number {
  return Math.max(1, ...downHist.value, ...upHist.value)
}

// x of point i, sliding left by one STEP over each interval so the newest
// sample enters from the right edge and settles at x = W.
function pts(data: number[], p: number): [number, number][] {
  const n = data.length
  const mx = peak()
  const dx = (1 - p) * STEP
  return data.map((v, i) => {
    const x = W - (n - 1 - i) * STEP + dx
    const y = H - (v / mx) * (H - 8) - 4
    return [x, y]
  })
}

// Catmull-Rom spline → cubic béziers for a curve that flows through each point.
function line(data: number[]): string {
  const p = pts(data, progress.value)
  if (p.length < 2) return p.length ? `M ${p[0][0]},${p[0][1]}` : ''
  let d = `M ${p[0][0].toFixed(1)},${p[0][1].toFixed(1)}`
  for (let i = 0; i < p.length - 1; i++) {
    const a = p[i - 1] || p[i]
    const b = p[i]
    const c = p[i + 1]
    const e = p[i + 2] || c
    const c1x = b[0] + (c[0] - a[0]) / 6
    const c1y = b[1] + (c[1] - a[1]) / 6
    const c2x = c[0] - (e[0] - b[0]) / 6
    const c2y = c[1] - (e[1] - b[1]) / 6
    d += ` C ${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${c[0].toFixed(1)},${c[1].toFixed(1)}`
  }
  return d
}

function area(data: number[]): string {
  const l = line(data)
  if (!l || data.length < 2) return ''
  const p = pts(data, progress.value)
  const lastX = p[p.length - 1][0]
  const firstX = p[0][0]
  return `${l} L ${lastX.toFixed(1)},${H} L ${firstX.toFixed(1)},${H} Z`
}
</script>

<style scoped>
.spark {
  width: 100%;
  height: 120px;
  display: block;
  background: var(--paper-bg);
  border-radius: var(--radius-sm);
  border: 1px solid var(--paper-border);
  margin-bottom: 0.6rem;
}
</style>
