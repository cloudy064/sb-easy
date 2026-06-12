import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import client from '../api/client'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('sb-easy-token') || '')
  const username = ref(localStorage.getItem('sb-easy-username') || '')
  const isAuthenticated = computed(() => !!token.value)

  async function login(password: string) {
    const { data } = await client.post('/auth/login', { password })
    token.value = data.token
    username.value = data.username
    localStorage.setItem('sb-easy-token', data.token)
    localStorage.setItem('sb-easy-username', data.username)
  }

  function logout() {
    token.value = ''
    username.value = ''
    localStorage.removeItem('sb-easy-token')
    localStorage.removeItem('sb-easy-username')
  }

  return { token, username, isAuthenticated, login, logout }
})
