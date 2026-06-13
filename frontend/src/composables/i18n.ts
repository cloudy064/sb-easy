import { ref, computed } from 'vue'

export type Locale = 'en' | 'zh'

const STORAGE_KEY = 'sb-easy-locale'

const messages: Record<Locale, Record<string, string>> = {
  en: {
    'nav.dashboard': 'Dashboard',
    'nav.monitor': 'Monitor',
    'nav.clients': 'Clients',
    'nav.nodes': 'Nodes',
    'nav.proxies': 'Proxies',
    'nav.subscriptions': 'Subscriptions',
    'nav.config': 'Config',
    'nav.users': 'Users',
    'nav.settings': 'Settings',
    'action.signout': 'Sign out',

    'page.dashboard.title': 'Dashboard',
    'page.dashboard.desc': 'Overview of your VPN clients, proxy nodes, and subscriptions.',
    'page.monitor.title': 'Monitor',
    'page.monitor.desc': 'Live traffic, connections, and logs from the running sing-box.',
    'page.clients.title': 'Clients',
    'page.clients.desc': 'Manage VPN clients, download configs, and monitor connections.',
    'page.nodes.title': 'Nodes',
    'page.nodes.desc': 'Manage proxy outbound nodes. Import via subscriptions or add manually.',
    'page.proxies.title': 'Proxies',
    'page.proxies.desc': 'Proxy groups and outbound selection, live from the running sing-box.',
    'page.subscriptions.title': 'Subscriptions',
    'page.config.title': 'Config',
    'page.config.desc': 'The sing-box config generated from your enabled nodes. This is what the agent fetches.',
    'page.users.title': 'Users & Audit',
    'page.users.desc': 'Manage accounts and review recent changes. Admin only.',
    'page.settings.title': 'Settings',

    'login.subtitle': 'WireGuard & Sing-box Management',
    'login.username': 'Username',
    'login.password': 'Password',
    'login.signin': 'Sign In',
  },
  zh: {
    'nav.dashboard': '仪表盘',
    'nav.monitor': '实时监控',
    'nav.clients': '客户端',
    'nav.nodes': '节点',
    'nav.proxies': '代理组',
    'nav.subscriptions': '订阅',
    'nav.config': '配置',
    'nav.users': '用户',
    'nav.settings': '设置',
    'action.signout': '退出登录',

    'page.dashboard.title': '仪表盘',
    'page.dashboard.desc': 'VPN 客户端、代理节点与订阅总览。',
    'page.monitor.title': '实时监控',
    'page.monitor.desc': '来自运行中 sing-box 的实时流量、连接与日志。',
    'page.clients.title': '客户端',
    'page.clients.desc': '管理 VPN 客户端、下载配置并监控连接。',
    'page.nodes.title': '节点',
    'page.nodes.desc': '管理代理出站节点。可从订阅导入或手动添加。',
    'page.proxies.title': '代理组',
    'page.proxies.desc': '来自运行中 sing-box 的代理组与出站选择。',
    'page.subscriptions.title': '订阅',
    'page.config.title': '配置',
    'page.config.desc': '根据已启用节点生成的 sing-box 配置，也是 agent 拉取的内容。',
    'page.users.title': '用户与审计',
    'page.users.desc': '管理账号并查看近期变更。仅管理员可见。',
    'page.settings.title': '设置',

    'login.subtitle': 'WireGuard 与 Sing-box 管理',
    'login.username': '用户名',
    'login.password': '密码',
    'login.signin': '登录',
  },
}

const locale = ref<Locale>('en')

export function initLocale() {
  const stored = localStorage.getItem(STORAGE_KEY) as Locale | null
  const guess: Locale = navigator.language?.toLowerCase().startsWith('zh') ? 'zh' : 'en'
  setLocale(stored ?? guess)
}

export function setLocale(l: Locale) {
  locale.value = l
  localStorage.setItem(STORAGE_KEY, l)
  document.documentElement.setAttribute('lang', l === 'zh' ? 'zh-CN' : 'en')
}

export function useI18n() {
  const t = (key: string) => messages[locale.value][key] ?? messages.en[key] ?? key
  function toggle() {
    setLocale(locale.value === 'zh' ? 'en' : 'zh')
  }
  return { locale: computed(() => locale.value), t, toggle, setLocale }
}
