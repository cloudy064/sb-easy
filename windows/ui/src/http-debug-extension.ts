import { createApp } from 'vue'
import HttpDebugView from './components/HttpDebugView.vue'
import type { NativeBridge } from './lib/bridge'
export function mount(element: HTMLElement, options: { bridge: NativeBridge }): () => void {
  const app = createApp(HttpDebugView, options); app.mount(element); return () => app.unmount()
}
