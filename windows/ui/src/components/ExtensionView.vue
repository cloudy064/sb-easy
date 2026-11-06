<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import type { ExtensionId } from '../lib/protocol'
import type { NativeBridge } from '../lib/bridge'
import { validExtensionRequest, validFrameMessage } from '../lib/extensions'
const props = defineProps<{ bridge: NativeBridge; server: string; id: ExtensionId }>()
const emit = defineEmits<{ back: [] }>()
const frame = ref<HTMLIFrameElement | null>(null), error = ref(''), height = ref(640)
const channel = [...crypto.getRandomValues(new Uint8Array(16))].map(v => v.toString(16).padStart(2, '0')).join('')
const source = `/plugin-frame.html#${props.id}/${channel}`
const pending = new Set<string>()
let disposed = false
function post(data: object) { frame.value?.contentWindow?.postMessage({ ...data, channel }, '*') }
function initialize() {
  const styles = [...document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]')].map(link => link.href)
    .filter(url => new URL(url).origin === location.origin && new URL(url).pathname.startsWith('/assets/'))
  post({ type: 'initialize', server: props.server, styles, theme: document.documentElement.dataset.theme ?? 'system' })
}
async function receive(event: MessageEvent) {
  if (disposed || !validFrameMessage(event, frame.value?.contentWindow ?? null, channel)) return
  const data = event.data
  if (data.type === 'ready') { initialize(); return }
  if (data.type === 'height' && Number.isFinite(data.height)) { height.value = Math.min(12000, Math.max(320, data.height)); return }
  if (data.type === 'error') { error.value = '扩展页面无法加载，请重新安装与当前版本兼容的扩展。代理连接不受影响。'; return }
  if (data.type !== 'request') return
  if (!validExtensionRequest(props.id, data) || pending.size >= 16 || pending.has(data.id)) {
    if (typeof data.id === 'string' && data.id.length <= 128) post({ type: 'response', id: data.id, ok: false, error: { code: 'EXTENSION_PERMISSION', message: '此扩展不能执行该请求' } })
    return
  }
  pending.add(data.id)
  try {
    const result = await props.bridge.request(data.method, data.params, { timeoutMs: data.timeoutMs })
    if (!disposed) post({ type: 'response', id: data.id, ok: true, result })
  } catch (failure) {
    if (!disposed) post({ type: 'response', id: data.id, ok: false, error: { code: 'EXTENSION_REQUEST_FAILED', message: failure instanceof Error ? failure.message : '扩展请求未完成' } })
  } finally { pending.delete(data.id) }
}
onMounted(() => window.addEventListener('message', receive))
onBeforeUnmount(() => { disposed = true; window.removeEventListener('message', receive); pending.clear() })
</script>
<template><button class="text-button" @click="emit('back')">← 返回扩展管理</button><p v-if="error" class="notice error" role="alert">{{ error }}</p><iframe ref="frame" :src="source" title="扩展工具" sandbox="allow-scripts allow-downloads" referrerpolicy="no-referrer" :style="{ height: `${height}px` }" @load="initialize" /></template>
<style scoped>iframe{display:block;width:100%;border:0;margin-top:16px;min-height:320px;color-scheme:light dark}</style>
