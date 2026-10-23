<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-mark">
        <img src="/sb-easy-mark.svg" alt="" />
      </div>
      <h1 class="login-title">sb-easy</h1>
      <p class="login-desc">{{ t('login.subtitle') }}</p>

      <form @submit.prevent="doLogin" class="login-form">
        <div v-if="!challenge" class="form-group">
          <label>{{ t('login.username') }}</label>
          <input
            v-model="username"
            type="text"
            placeholder="admin"
            autocomplete="username"
            class="login-input"
          />
        </div>
        <div v-if="!challenge" class="form-group">
          <label>{{ t('login.password') }}</label>
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            class="login-input"
          />
        </div>
        <div v-if="challenge" class="form-group">
          <label>{{ locale === 'zh' ? '验证码或恢复码' : 'Authenticator or recovery code' }}</label>
          <input v-model="code" autocomplete="one-time-code" required class="login-input" />
          <p class="text-sm text-muted">{{ locale === 'zh' ? '输入认证器中的六位验证码，或一个未使用的恢复码。' : 'Enter the six-digit authenticator code or an unused recovery code.' }}</p>
        </div>
        <button type="submit" class="btn-primary w-full login-btn" :disabled="loading">
          <span v-if="loading" class="spinner" style="width:16px;height:16px;border-width:1.5px"></span>
          <span v-else>{{ t('login.signin') }}</span>
        </button>
      </form>
      <button v-if="challenge" class="btn-ghost w-full" @click="challenge = ''; code = ''">{{ locale === 'zh' ? '返回登录' : 'Back to sign in' }}</button>
      <button v-if="oidcEnabled && !challenge" class="btn-secondary w-full" style="margin-top:1rem" :disabled="loading" @click="startOidc">{{ locale === 'zh' ? '使用组织账户登录' : 'Sign in with your organization' }}</button>

      <p v-if="error" class="login-error">{{ error }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore, type LoginResult } from '../stores/auth'
import client from '../api/client'
import { useI18n } from '../composables/i18n'

const { t, locale } = useI18n()
const router = useRouter()
const auth = useAuthStore()
const username = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')
const challenge = ref('')
const code = ref('')
const oidcEnabled = ref(false)

function finish(data: LoginResult) {
  password.value = ''; code.value = ''
  if (data.mfa_required && data.challenge) challenge.value = data.challenge
  else if (data.token) router.replace(auth.isAdmin ? '/' : '/devices')
}
async function startOidc() {
  loading.value = true; error.value = ''
  try { const { data } = await client.post('/auth/oidc/start'); window.location.assign(data.authorization_url) }
  catch (e: any) { error.value = e.response?.data?.error || 'Sign in failed'; loading.value = false }
}
onMounted(async () => {
  const params = new URLSearchParams(window.location.search)
  const state = params.get('state'), authorizationCode = params.get('code'), providerError = params.get('error')
  if (state || authorizationCode || providerError) {
    window.history.replaceState({}, '', '/login')
    loading.value = true
    try {
      if (providerError || !state || !authorizationCode) throw new Error('Organization sign in was not completed')
      finish(await auth.completeOidc(state, authorizationCode))
    } catch (e: any) { error.value = e.response?.data?.error || e.message || 'Sign in failed' }
    finally { loading.value = false }
  }
  try { const { data } = await client.get('/auth/oidc'); oidcEnabled.value = data.enabled === true } catch { /* password login remains available */ }
})

async function doLogin() {
  error.value = ''
  loading.value = true
  try {
    finish(challenge.value ? await auth.completeMfa(challenge.value, code.value.trim()) : await auth.login(password.value, username.value || undefined))
  } catch (e: any) {
    error.value = e.response?.data?.error || 'Login failed'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: var(--paper-bg);
}

.login-card {
  background: var(--paper-surface);
  border: 1px solid var(--paper-border);
  border-radius: var(--radius-xl);
  box-shadow:
    0 0 0 1px rgba(0,0,0,.02),
    0 2px 8px rgba(0,0,0,.03),
    0 16px 48px rgba(0,0,0,.06);
  padding: 2.75rem 2.5rem;
  width: 100%;
  max-width: 400px;
}

.login-mark {
  width: 68px;
  height: 68px;
  display: grid;
  place-items: center;
  padding: 7px;
  margin-left: auto;
  margin-right: auto;
  margin-bottom: 1.25rem;
  border-radius: 20px;
  background: #0b1118;
  box-shadow: 0 8px 24px rgba(11, 17, 24, 0.16);
}

.login-mark img { width: 100%; height: 100%; display: block; }

.login-title {
  text-align: center;
  font-size: 1.5rem;
  font-weight: 680;
  color: var(--ink-primary);
  margin-bottom: 0.3rem;
}

.login-desc {
  text-align: center;
  font-size: 0.85rem;
  color: var(--ink-muted);
  margin-bottom: 2rem;
}

.login-form {
  margin-bottom: 0;
}

.login-input {
  padding: 0.65rem 0.9rem;
  font-size: 0.9rem;
}

.login-btn {
  margin-top: 0.5rem;
  padding: 0.65rem;
  font-size: 0.9rem;
}

.login-error {
  margin-top: 1rem;
  padding: 0.65rem 0.85rem;
  border-radius: var(--radius-sm);
  background: var(--bad-bg);
  color: var(--bad);
  font-size: 0.82rem;
  text-align: center;
  border: 1px solid #f0c8c4;
}
</style>
