import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import client from '../api/client'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('sb-easy-token') || '')
  const username = ref(localStorage.getItem('sb-easy-username') || '')
  const role = ref(localStorage.getItem('sb-easy-role') || 'admin')
  const isAuthenticated = computed(() => !!token.value)
  const isAdmin = computed(() => role.value === 'admin')

  async function login(password: string, usernameInput?: string) {
    const payload: Record<string, string> = { password }
    if (usernameInput) payload.username = usernameInput
    const { data } = await client.post('/auth/login', payload)
    token.value = data.token
    username.value = data.username
    role.value = data.role || 'admin'
    localStorage.setItem('sb-easy-token', data.token)
    localStorage.setItem('sb-easy-username', data.username)
    localStorage.setItem('sb-easy-role', role.value)
  }

  function logout() {
    token.value = ''
    username.value = ''
    role.value = 'admin'
    localStorage.removeItem('sb-easy-token')
    localStorage.removeItem('sb-easy-username')
    localStorage.removeItem('sb-easy-role')
  }

  return { token, username, role, isAuthenticated, isAdmin, login, logout }
})
