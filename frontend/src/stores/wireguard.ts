import { defineStore } from 'pinia'
import { ref } from 'vue'
import client from '../api/client'
import type { WireGuardPeer } from '../types'

export const useWireGuardStore = defineStore('wireguard', () => {
  const peers = ref<WireGuardPeer[]>([])
  const loading = ref(false)

  async function fetchPeers() {
    loading.value = true
    try {
      const { data } = await client.get('/wireguard/peers')
      peers.value = data
    } finally {
      loading.value = false
    }
  }

  async function createPeer(req: any) {
    const { data } = await client.post('/wireguard/peers', req)
    peers.value.push(data)
    return data
  }

  async function updatePeer(id: string, req: any) {
    const { data } = await client.put(`/wireguard/peers/${id}`, req)
    const idx = peers.value.findIndex(p => p.id === id)
    if (idx >= 0) peers.value[idx] = data
    return data
  }

  async function deletePeer(id: string) {
    await client.delete(`/wireguard/peers/${id}`)
    peers.value = peers.value.filter(p => p.id !== id)
  }

  async function togglePeer(id: string, enable: boolean) {
    const endpoint = enable ? 'enable' : 'disable'
    await client.post(`/wireguard/peers/${id}/${endpoint}`)
    const peer = peers.value.find(p => p.id === id)
    if (peer) peer.enabled = enable
  }

  function getConfigUrl(id: string) {
    return `/api/wireguard/peers/${id}/config`
  }

  return { peers, loading, fetchPeers, createPeer, updatePeer, deletePeer, togglePeer, getConfigUrl }
})
