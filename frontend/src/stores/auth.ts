import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import client from '../api/client'

export interface LoginResult { token?: string; username?: string; role?: string; mfa_required?: boolean; challenge?: string }
export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('sb-easy-token') || '')
  const username = ref(localStorage.getItem('sb-easy-username') || '')
  const role = ref(localStorage.getItem('sb-easy-role') || 'viewer')
  const isAuthenticated = computed(() => !!token.value)
  const isAdmin = computed(() => role.value === 'admin')
  function accept(data: LoginResult) {
    if (!data.token) return data
    token.value = data.token
    username.value = data.username || ''
    role.value = data.role || 'viewer'
    localStorage.setItem('sb-easy-token', token.value)
    localStorage.setItem('sb-easy-username', username.value)
    localStorage.setItem('sb-easy-role', role.value)
    return data
  }
  async function login(password: string, usernameInput?: string) {
    const { data } = await client.post<LoginResult>('/auth/login', { password, ...(usernameInput ? { username: usernameInput } : {}) })
    return accept(data)
  }
  async function completeMfa(challenge: string, code: string) {
    const { data } = await client.post<LoginResult>('/auth/login/mfa', { challenge, code })
    return accept(data)
  }
  async function completeOidc(state: string, code: string) {
    const { data } = await client.post<LoginResult>('/auth/oidc/finish', { state, code })
    return accept(data)
  }
  function clear() {
    token.value = ''; username.value = ''; role.value = 'viewer'
    localStorage.removeItem('sb-easy-token'); localStorage.removeItem('sb-easy-username'); localStorage.removeItem('sb-easy-role')
  }
  async function logout() {
    if (token.value) await client.post('/auth/logout')
    clear()
  }
  return { token, username, role, isAuthenticated, isAdmin, login, completeMfa, completeOidc, logout, clear }
})
