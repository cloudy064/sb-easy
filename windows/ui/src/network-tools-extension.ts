import { createApp } from 'vue'
import NetworkToolsView from './components/NetworkToolsView.vue'
import type { NativeBridge } from './lib/bridge'
export function mount(element: HTMLElement, options: { bridge: NativeBridge }): () => void {
  const app = createApp(NetworkToolsView, options); app.mount(element); return () => app.unmount()
}
