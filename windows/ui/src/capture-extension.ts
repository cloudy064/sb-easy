import { createApp } from 'vue'
import CaptureView from './components/CaptureView.vue'
import type { NativeBridge } from './lib/bridge'
export function mount(element: HTMLElement, options: { bridge: NativeBridge; server: string }): () => void {
  const app = createApp(CaptureView, options)
  app.mount(element)
  return () => app.unmount()
}
