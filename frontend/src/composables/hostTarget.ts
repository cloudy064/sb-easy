// Shared "which host am I observing" selection for the live views
// (Monitor / Proxies / Logs). The selection is a module-level singleton so it
// persists as the user moves between those views.
import { ref, computed } from 'vue'
import client from '../api/client'
import type { Host } from '../types'

// '' or 'self' = the local sing-box (this server); otherwise a managed host id.
const selectedHost = ref<string>('self')
const hosts = ref<Host[]>([])

export function useHostTarget() {
  async function fetchHosts() {
    const { data } = await client.get('/hosts')
    // Only hosts that run sing-box can serve live data; a non-self host needs a
    // reachable Clash API (over WG) to actually return anything.
    const list = Array.isArray(data) ? (data as Host[]) : []
    hosts.value = list.filter((h) => h.capabilities?.runs_singbox)
    // Keep the current selection if it still runs sing-box; otherwise prefer the
    // local host when *it* runs sing-box, else fall back to the first host that
    // does (e.g. on a control-only server the agent is the live target).
    if (!hosts.value.some((h) => h.id === selectedHost.value)) {
      const selfRuns = hosts.value.some((h) => h.id === 'self' || h.capabilities?.is_self)
      selectedHost.value = selfRuns ? 'self' : (hosts.value[0]?.id ?? 'self')
    }
  }

  // Query params for REST calls; empty object for the local host.
  const reqParams = computed(() =>
    selectedHost.value && selectedHost.value !== 'self' ? { host: selectedHost.value } : {},
  )

  return { hosts, selectedHost, fetchHosts, reqParams }
}
