<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import type { ExtensionId } from '../lib/protocol'
import type { NativeBridge } from '../lib/bridge'
const props = defineProps<{ bridge: NativeBridge; server: string; id: ExtensionId }>()
const emit = defineEmits<{ back: [] }>()
const container = ref<HTMLElement | null>(null), error = ref('')
let disposed = false, unmount: (() => void) | undefined
const style = document.createElement('link')
onMounted(async () => {
  try {
    style.rel = 'stylesheet'; style.href = `./extensions/${props.id}/view.css`; document.head.appendChild(style)
    const url = new URL(`./extensions/${props.id}/view.js`, window.location.href).href
    const extension = await import(/* @vite-ignore */ url)
    if (!disposed && container.value) unmount = extension.mount(container.value, { bridge: props.bridge, server: props.server })
  } catch (cause) { console.error('Extension module could not load', cause); error.value = '扩展页面无法加载，请重新安装与当前版本兼容的扩展。代理连接不受影响。' }
})
onBeforeUnmount(() => { disposed = true; unmount?.(); style.remove() })
</script>
<template><button class="text-button" @click="emit('back')">← 返回扩展管理</button><p v-if="error" class="notice error">{{ error }}</p><div ref="container"></div></template>
