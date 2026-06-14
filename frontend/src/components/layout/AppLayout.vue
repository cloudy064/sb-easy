<template>
  <div class="app-layout">
    <aside class="sidebar" :class="{ open: sidebarOpen }">
      <div class="sidebar-brand">
        <svg class="brand-mark" width="28" height="28" viewBox="0 0 28 28" fill="none">
          <rect x="2" y="2" width="24" height="24" rx="6" stroke="currentColor" stroke-width="2"/>
          <path d="M8 14l4 4 8-8" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span class="sidebar-title">sb-easy</span>
      </div>

      <nav class="sidebar-nav">
        <router-link to="/" class="nav-item" exact-active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <rect x="1" y="1" width="6" height="6" rx="1"/><rect x="11" y="1" width="6" height="6" rx="1"/>
            <rect x="1" y="11" width="6" height="6" rx="1"/><rect x="11" y="11" width="6" height="6" rx="1"/>
          </svg>
          {{ t('nav.dashboard') }}
        </router-link>
        <router-link to="/monitor" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M1 12l4-5 3 3 4-6 4 8" stroke-linecap="round" stroke-linejoin="round"/><path d="M1 16h16"/>
          </svg>
          {{ t('nav.monitor') }}
        </router-link>
        <router-link to="/logs" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M3 2h9l3 3v11H3z"/><path d="M6 7h6M6 10h6M6 13h4"/>
          </svg>
          {{ t('nav.logs') }}
        </router-link>
        <router-link to="/hosts" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <rect x="1" y="2" width="16" height="6" rx="1"/><rect x="1" y="10" width="16" height="6" rx="1"/>
            <circle cx="4" cy="5" r="0.8" fill="currentColor"/><circle cx="4" cy="13" r="0.8" fill="currentColor"/>
          </svg>
          {{ t('nav.hosts') }}
        </router-link>
        <router-link to="/profiles" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M3 2h9l3 3v11H3z"/><path d="M6 7h6M6 10h6M6 13h3"/><path d="M12 2v3h3"/>
          </svg>
          {{ t('nav.profiles') }}
        </router-link>
        <router-link to="/clients" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M9 1v16M1 9h16"/><circle cx="9" cy="9" r="2"/><circle cx="9" cy="1" r="1.5"/>
            <circle cx="9" cy="17" r="1.5"/><circle cx="1" cy="9" r="1.5"/><circle cx="17" cy="9" r="1.5"/>
          </svg>
          {{ t('nav.clients') }}
        </router-link>
        <router-link to="/nodes" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <circle cx="9" cy="9" r="7"/><circle cx="9" cy="9" r="2"/><path d="M9 2v14M2 9h14"/>
            <path d="M4 4c2 1.5 4 3 5 5 1-2 3-3.5 5-5M4 14c2-1.5 4-3 5-5 1 2 3 3.5 5 5"/>
          </svg>
          {{ t('nav.nodes') }}
        </router-link>
        <router-link to="/proxies" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <rect x="1" y="2" width="16" height="4" rx="1"/><rect x="1" y="8" width="16" height="4" rx="1"/>
            <rect x="1" y="14" width="10" height="2.5" rx="1"/>
          </svg>
          {{ t('nav.proxies') }}
        </router-link>
        <router-link to="/subscriptions" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M1 7l4-4 3 3 9-5"/><path d="M1 13l4-4 3 3 9-5"/>
          </svg>
          {{ t('nav.subscriptions') }}
        </router-link>
        <router-link to="/config" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M6 4L2 9l4 5M12 4l4 5-4 5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          {{ t('nav.config') }}
        </router-link>
        <router-link v-if="isAdmin" to="/users" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <circle cx="6.5" cy="6" r="2.5"/><path d="M2 16c0-2.5 2-4 4.5-4s4.5 1.5 4.5 4"/>
            <circle cx="13" cy="7" r="2"/><path d="M12 12c2 0 4 1.2 4 4"/>
          </svg>
          {{ t('nav.users') }}
        </router-link>
        <router-link to="/settings" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <circle cx="9" cy="9" r="3"/><path d="M9 1v2M9 15v2M1 9h2M15 9h2M3.5 3.5l1.4 1.4M13.1 13.1l1.4 1.4M3.5 14.5l1.4-1.4M13.1 4.9l1.4-1.4"/>
          </svg>
          {{ t('nav.settings') }}
        </router-link>
      </nav>

      <div class="sidebar-footer">
        <span class="sidebar-user">{{ username }}</span>
        <div class="flex-center gap-2">
          <button class="btn-ghost btn-xs" @click="toggleLocale" :title="locale === 'zh' ? 'English' : '中文'">
            {{ locale === 'zh' ? 'EN' : '中' }}
          </button>
          <button class="btn-ghost btn-xs" @click="toggle" :title="theme === 'dark' ? 'Light mode' : 'Dark mode'">
            {{ theme === 'dark' ? '☀' : '☾' }}
          </button>
          <button class="btn-ghost btn-xs" @click="logout">{{ t('action.signout') }}</button>
        </div>
      </div>
    </aside>

    <div v-if="sidebarOpen" class="sidebar-scrim" @click="sidebarOpen = false"></div>

    <main class="main-content">
      <button class="mobile-menu-btn" @click="sidebarOpen = true" aria-label="Open menu">
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M3 5h14M3 10h14M3 15h14" stroke-linecap="round"/>
        </svg>
      </button>
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../../stores/auth'
import { useTheme } from '../../composables/theme'
import { useI18n } from '../../composables/i18n'

const auth = useAuthStore()
const router = useRouter()
const username = auth.username
const isAdmin = auth.isAdmin
const { theme, toggle } = useTheme()
const { t, locale, toggle: toggleLocale } = useI18n()

const sidebarOpen = ref(false)
// Close the mobile drawer on navigation.
watch(() => router.currentRoute.value.path, () => (sidebarOpen.value = false))

function logout() {
  auth.logout()
  router.push('/login')
}
</script>

<style scoped>
.app-layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

.sidebar {
  width: 240px;
  background: var(--paper-surface);
  border-right: 1px solid var(--paper-border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  height: 100vh;
}

.sidebar-brand {
  padding: 1.4rem 1.25rem;
  display: flex;
  align-items: center;
  gap: 0.6rem;
  border-bottom: 1px solid var(--paper-border);
  flex-shrink: 0;
}

.brand-mark {
  color: var(--accent);
  flex-shrink: 0;
}

.sidebar-title {
  font-size: 1.05rem;
  font-weight: 680;
  color: var(--ink-primary);
  letter-spacing: -0.02em;
}

.sidebar-nav {
  flex: 1;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 3px;
  overflow-y: auto;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  padding: 0.6rem 0.85rem;
  border-radius: var(--radius-sm);
  color: var(--ink-secondary);
  font-size: 0.85rem;
  font-weight: 500;
  text-decoration: none;
  transition: all 0.15s ease;
  letter-spacing: -0.01em;
}

.nav-item:hover {
  background: var(--paper-bg);
  color: var(--ink-primary);
}

.nav-item.active {
  background: var(--accent-subtle);
  color: var(--accent);
  font-weight: 600;
}

.nav-icon {
  flex-shrink: 0;
  opacity: 0.55;
  transition: opacity 0.15s;
}

.nav-item:hover .nav-icon,
.nav-item.active .nav-icon {
  opacity: 1;
}

.sidebar-footer {
  padding: 0.85rem 1.25rem;
  border-top: 1px solid var(--paper-border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-shrink: 0;
}

.sidebar-user {
  font-size: 0.8rem;
  color: var(--ink-muted);
  font-weight: 500;
}

.main-content {
  flex: 1;
  padding: 2.75rem 3rem;
  overflow-y: auto;
  height: 100vh;
}

.mobile-menu-btn {
  display: none;
  background: var(--paper-surface);
  border: 1px solid var(--paper-border);
  color: var(--ink-secondary);
  border-radius: var(--radius-sm);
  padding: 0.4rem;
  margin-bottom: 1.25rem;
}

.sidebar-scrim { display: none; }

/* ── Responsive: sidebar becomes a slide-over drawer ── */
@media (max-width: 768px) {
  .sidebar {
    position: fixed;
    top: 0; left: 0;
    z-index: 1100;
    transform: translateX(-100%);
    transition: transform 0.22s ease;
    box-shadow: var(--paper-shadow-hover);
  }
  .sidebar.open { transform: translateX(0); }
  .sidebar-scrim {
    display: block;
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,.35);
    z-index: 1050;
  }
  .main-content { padding: 1.5rem 1.25rem; }
  .mobile-menu-btn { display: inline-flex; }
}
</style>
