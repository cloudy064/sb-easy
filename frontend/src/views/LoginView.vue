<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-mark">
        <svg width="36" height="36" viewBox="0 0 28 28" fill="none">
          <rect x="2" y="2" width="24" height="24" rx="6" stroke="currentColor" stroke-width="2"/>
          <path d="M8 14l4 4 8-8" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <h1 class="login-title">sb-easy</h1>
      <p class="login-desc">{{ t('login.subtitle') }}</p>

      <form @submit.prevent="doLogin" class="login-form">
        <div class="form-group">
          <label>{{ t('login.username') }}</label>
          <input
            v-model="username"
            type="text"
            placeholder="admin"
            autocomplete="username"
            class="login-input"
          />
        </div>
        <div class="form-group">
          <label>{{ t('login.password') }}</label>
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            class="login-input"
          />
        </div>
        <button type="submit" class="btn-primary w-full login-btn" :disabled="loading">
          <span v-if="loading" class="spinner" style="width:16px;height:16px;border-width:1.5px"></span>
          <span v-else>{{ t('login.signin') }}</span>
        </button>
      </form>

      <p v-if="error" class="login-error">{{ error }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { useI18n } from '../composables/i18n'

const { t } = useI18n()
const router = useRouter()
const auth = useAuthStore()
const username = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')

async function doLogin() {
  error.value = ''
  loading.value = true
  try {
    await auth.login(password.value, username.value || undefined)
    router.push('/')
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
  background: var(--nm-card-bg);
  border: none;
  border-radius: var(--radius-xl);
  box-shadow: 8px 8px 24px rgba(0,0,0,.08), -8px -8px 24px var(--nm-light),
              0 0 0 1px rgba(0,0,0,.02);
  padding: 2.75rem 2.5rem;
  width: 100%;
  max-width: 400px;
}

.login-mark {
  color: var(--accent);
  text-align: center;
  margin-bottom: 1.25rem;
}

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
  border: none;
  box-shadow: var(--nm-shadow-sm-in);
}
</style>
