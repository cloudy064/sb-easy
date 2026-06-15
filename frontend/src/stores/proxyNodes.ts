import { defineStore } from 'pinia'
import { ref } from 'vue'
import client from '../api/client'
import type { ProxyNode } from '../types'

export const useProxyNodesStore = defineStore('proxyNodes', () => {
  const nodes = ref<ProxyNode[]>([])
  const loading = ref(false)

  async function fetchNodes() {
    loading.value = true
    try {
      const { data } = await client.get('/proxy/nodes')
      nodes.value = data
    } finally {
      loading.value = false
    }
  }

  async function createNode(req: any) {
    const { data } = await client.post('/proxy/nodes', req)
    nodes.value.push(data)
    return data
  }

  async function updateNode(id: string, req: any) {
    const { data } = await client.put(`/proxy/nodes/${id}`, req)
    const idx = nodes.value.findIndex(n => n.id === id)
    if (idx >= 0) nodes.value[idx] = data
    return data
  }

  async function deleteNode(id: string) {
    await client.delete(`/proxy/nodes/${id}`)
    nodes.value = nodes.value.filter(n => n.id !== id)
  }

  async function testLatency(id: string) {
    const { data } = await client.post(`/proxy/nodes/${id}/test-latency`)
    const node = nodes.value.find(n => n.id === id)
    if (node) node.latency = data.latency
    return data
  }

  // Import proxy nodes from an existing config profile or pasted sing-box JSON.
  // Additive (dedupes by fingerprint); does not change any running config.
  async function importNodes(body: { profile_id?: string; config?: string }) {
    const { data } = await client.post('/proxy/nodes/import', body)
    await fetchNodes()
    return data as { found: number; added: number; updated: number; skipped: string[]; errors: string[] }
  }

  return { nodes, loading, fetchNodes, createNode, updateNode, deleteNode, testLatency, importNodes }
})
