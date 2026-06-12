<template>
  <div class="app-layout">
    <aside class="sidebar">
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
          Dashboard
        </router-link>
        <router-link to="/clients" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M9 1v16M1 9h16"/><circle cx="9" cy="9" r="2"/><circle cx="9" cy="1" r="1.5"/>
            <circle cx="9" cy="17" r="1.5"/><circle cx="1" cy="9" r="1.5"/><circle cx="17" cy="9" r="1.5"/>
          </svg>
          Clients
        </router-link>
        <router-link to="/nodes" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <circle cx="9" cy="9" r="7"/><circle cx="9" cy="9" r="2"/><path d="M9 2v14M2 9h14"/>
            <path d="M4 4c2 1.5 4 3 5 5 1-2 3-3.5 5-5M4 14c2-1.5 4-3 5-5 1 2 3 3.5 5 5"/>
          </svg>
          Nodes
        </router-link>
        <router-link to="/subscriptions" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <path d="M1 7l4-4 3 3 9-5"/><path d="M1 13l4-4 3 3 9-5"/>
          </svg>
          Subscriptions
        </router-link>
        <router-link to="/settings" class="nav-item" active-class="active">
          <svg class="nav-icon" width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.6">
            <circle cx="9" cy="9" r="3"/><path d="M9 1v2M9 15v2M1 9h2M15 9h2M3.5 3.5l1.4 1.4M13.1 13.1l1.4 1.4M3.5 14.5l1.4-1.4M13.1 4.9l1.4-1.4"/>
          </svg>
          Settings
        </router-link>
      </nav>

      <div class="sidebar-footer">
        <span class="sidebar-user">{{ username }}</span>
        <button class="btn-ghost btn-xs" @click="logout">Sign out</button>
      </div>
    </aside>

    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useAuthStore } from '../../stores/auth'

const auth = useAuthStore()
const router = useRouter()
const username = auth.username

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
  background: #f5f1e9;
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
</style>
