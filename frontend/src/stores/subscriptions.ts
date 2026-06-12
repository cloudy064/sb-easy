import { defineStore } from 'pinia'
import { ref } from 'vue'
import client from '../api/client'
import type { Subscription, FetchResult } from '../types'

export const useSubscriptionsStore = defineStore('subscriptions', () => {
  const subs = ref<Subscription[]>([])
  const loading = ref(false)

  async function fetchAll() {
    loading.value = true
    try {
      const { data } = await client.get('/subscriptions')
      subs.value = data
    } finally {
      loading.value = false
    }
  }

  async function create(req: { name: string; url: string; refresh_interval?: number }) {
    const { data } = await client.post('/subscriptions', req)
    subs.value.push(data)
    return data
  }

  async function remove(id: string) {
    await client.delete(`/subscriptions/${id}`)
    subs.value = subs.value.filter(s => s.id !== id)
  }

  async function fetchOne(id: string): Promise<FetchResult> {
    const { data } = await client.post(`/subscriptions/${id}/fetch`)
    return data
  }

  return { subs, loading, fetchAll, create, remove, fetchOne }
})
