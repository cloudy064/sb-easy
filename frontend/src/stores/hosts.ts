import { defineStore } from 'pinia'
import { ref } from 'vue'
import client from '../api/client'
import type { Host, ConfigProfile, HostCapabilities } from '../types'

export interface CreateHostBody {
  name: string
  capabilities?: Partial<HostCapabilities>
  profile_id?: string
  wg_address?: string
  clash_api?: string
  clash_secret?: string
}

export const useHostsStore = defineStore('hosts', () => {
  const hosts = ref<Host[]>([])
  const profiles = ref<ConfigProfile[]>([])
  const loading = ref(false)

  async function fetchHosts() {
    loading.value = true
    try {
      const { data } = await client.get('/hosts')
      hosts.value = data
    } finally {
      loading.value = false
    }
  }

  async function fetchProfiles() {
    const { data } = await client.get('/hosts/profiles')
    profiles.value = data
  }

  async function createHost(body: CreateHostBody): Promise<Host> {
    const { data } = await client.post('/hosts', body)
    await fetchHosts()
    return data
  }

  async function updateHost(id: string, body: Partial<Host>) {
    const { data } = await client.put(`/hosts/${id}`, body)
    const idx = hosts.value.findIndex(h => h.id === id)
    if (idx >= 0) hosts.value[idx] = { ...hosts.value[idx], ...data }
    return data
  }

  async function deleteHost(id: string) {
    await client.delete(`/hosts/${id}`)
    hosts.value = hosts.value.filter(h => h.id !== id)
  }

  async function revealToken(id: string): Promise<{ agent_token: string; server: string }> {
    const { data } = await client.get(`/hosts/${id}/token`)
    return data
  }

  async function rotateToken(id: string): Promise<string> {
    const { data } = await client.post(`/hosts/${id}/rotate-token`)
    return data.agent_token
  }

  async function getOutbounds(id: string): Promise<string[]> {
    const { data } = await client.get(`/hosts/${id}/outbounds`)
    return data.node_ids
  }

  async function setOutbounds(id: string, nodeIds: string[]) {
    await client.put(`/hosts/${id}/outbounds`, { node_ids: nodeIds })
    await fetchHosts()
  }

  async function downloadWgConfig(host: Host) {
    const { data } = await client.get(`/hosts/${host.id}/wg-config`, { responseType: 'blob' })
    const url = URL.createObjectURL(data as Blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${host.name.replace(/\s+/g, '_')}-wg.conf`
    a.click()
    URL.revokeObjectURL(url)
  }

  return {
    hosts, profiles, loading,
    fetchHosts, fetchProfiles, createHost, updateHost, deleteHost,
    revealToken, rotateToken, getOutbounds, setOutbounds, downloadWgConfig,
  }
})
