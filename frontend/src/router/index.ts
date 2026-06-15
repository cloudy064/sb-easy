import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: () => import('../views/LoginView.vue'),
    },
    {
      path: '/',
      component: () => import('../components/layout/AppLayout.vue'),
      meta: { requiresAuth: true },
      children: [
        { path: '', name: 'Dashboard', component: () => import('../views/DashboardView.vue') },
        { path: 'monitor', name: 'Monitor', component: () => import('../views/MonitorView.vue') },
        { path: 'logs', name: 'Logs', component: () => import('../views/LogsView.vue') },
        { path: 'devices', name: 'Devices', component: () => import('../views/DevicesView.vue') },
        { path: 'hosts', name: 'Hosts', component: () => import('../views/HostsView.vue') },
        { path: 'profiles', name: 'Profiles', component: () => import('../views/ProfilesView.vue') },
        // Clients are folded into the unified Devices view; keep the old path as a redirect.
        { path: 'clients', redirect: '/devices' },
        { path: 'nodes', name: 'Nodes', component: () => import('../views/NodesView.vue') },
        { path: 'proxies', name: 'Proxies', component: () => import('../views/ProxiesView.vue') },
        { path: 'subscriptions', name: 'Subscriptions', component: () => import('../views/SubscriptionsView.vue') },
        { path: 'config', name: 'Config', component: () => import('../views/ConfigView.vue') },
        { path: 'users', name: 'Users', component: () => import('../views/UsersView.vue') },
        { path: 'settings', name: 'Settings', component: () => import('../views/SettingsView.vue') },
      ],
    },
  ],
})

router.beforeEach((to, _from, next) => {
  const auth = useAuthStore()
  if (to.meta.requiresAuth && !auth.token) {
    next('/login')
  } else if (to.path === '/login' && auth.token) {
    next('/')
  } else if (to.name === 'Users' && auth.role !== 'admin') {
    next('/')
  } else {
    next()
  }
})

export default router
