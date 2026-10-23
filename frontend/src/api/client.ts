import axios from 'axios'

const client = axios.create({
  baseURL: '/api',
  timeout: 15000,
})

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('sb-easy-token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

client.interceptors.response.use(
  (response) => response,
  (error) => {
    const url = String(error.config?.url || '')
    const accountProof = /^\/auth\/(login|oidc|mfa|password)(\/|$)/.test(url)
    if (error.response?.status === 401 && !accountProof) {
      localStorage.removeItem('sb-easy-token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export default client
