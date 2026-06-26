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

  async function downloadConfig(id: string) {
    const response = await client.get(`/wireguard/peers/${id}/config`, { responseType: 'blob' })
    const url = window.URL.createObjectURL(response.data)
    const link = document.createElement('a')
    link.href = url
    const disposition = response.headers['content-disposition']
    let filename = 'client.conf'
    if (disposition) {
      const match = disposition.match(/filename="?([^"]+)"?/)
      if (match) filename = match[1]
    }
    link.setAttribute('download', filename)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
  }

  async function fetchQR(id: string): Promise<string> {
    const response = await client.get(`/wireguard/peers/${id}/qr`, { responseType: 'blob' })
    return window.URL.createObjectURL(response.data)
  }

  return { peers, loading, fetchPeers, createPeer, updatePeer, deletePeer, togglePeer, downloadConfig, fetchQR }
})
