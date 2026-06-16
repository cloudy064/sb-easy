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
        { path: 'devices', name: 'Devices', component: () => import('../views/DevicesView.vue') },
        // Config / Monitor / Logs are per-device — viewed inside a device's detail.
        { path: 'devices/:id', name: 'DeviceDetail', component: () => import('../views/DeviceDetailView.vue') },
        { path: 'server-logs', name: 'ServerLogs', component: () => import('../views/ServerLogsView.vue') },
        // Old top-level realtime/config pages now live per-device.
        { path: 'monitor', redirect: '/devices' },
        { path: 'logs', redirect: '/devices' },
        { path: 'config', redirect: '/devices' },
        { path: 'profiles', name: 'Profiles', component: () => import('../views/ProfilesView.vue') },
        // Hosts and Clients are both folded into the unified Devices view.
        { path: 'hosts', redirect: '/devices' },
        { path: 'clients', redirect: '/devices' },
        // The proxy node list is the primary "Proxies" page; the live Clash
        // selector view becomes "Proxy Groups".
        { path: 'proxies', name: 'Proxies', component: () => import('../views/NodesView.vue') },
        { path: 'nodes', redirect: '/proxies' },
        // Proxy Groups (live manual node-switching) is obsolete under the
        // simplified node+rules model — redirect any old links to the node list.
        { path: 'proxy-groups', redirect: '/proxies' },
        { path: 'subscriptions', name: 'Subscriptions', component: () => import('../views/SubscriptionsView.vue') },
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
