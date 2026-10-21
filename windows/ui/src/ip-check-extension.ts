import { createApp } from 'vue'
import IpCheckView from './components/IpCheckView.vue'
import type { NativeBridge } from './lib/bridge'

export function mount(element: HTMLElement, options: { bridge: NativeBridge }): () => void {
  const app = createApp(IpCheckView, options)
  app.mount(element)
  return () => app.unmount()
}
