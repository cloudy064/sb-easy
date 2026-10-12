import { createApp } from 'vue'
import StatisticsView from './components/StatisticsView.vue'
import type { NativeBridge } from './lib/bridge'
export function mount(element: HTMLElement, options: { bridge: NativeBridge }): () => void {
  const app = createApp(StatisticsView, options); app.mount(element); return () => app.unmount()
}
