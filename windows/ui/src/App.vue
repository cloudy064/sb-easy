<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import jsQR from 'jsqr'
import { onEnrollmentActivation, rpc } from './bridge'

type Page = 'dashboard' | 'proxies' | 'routing' | 'config' | 'logs' | 'settings'
type JsonObject = Record<string, any>
type Enrollment = {
  enrolled: boolean
  server?: string
  host_id?: string
  host_name?: string
  profile?: { id?: string; name?: string }
}

const pages: Array<{ id: Page; label: string; mark: string }> = [
  { id: 'dashboard', label: '概览', mark: '◫' },
  { id: 'proxies', label: '代理', mark: '⇄' },
  { id: 'routing', label: '路由', mark: '⌁' },
  { id: 'config', label: '运行配置', mark: '⌘' },
  { id: 'logs', label: '日志', mark: '≡' },
  { id: 'settings', label: '设置', mark: '⚙' },
]

const page = ref<Page>('dashboard')
const enrollment = ref<Enrollment>({ enrolled: false })
const status = ref<JsonObject>({})
const proxies = ref<any[]>([])
const routes = ref<any[]>([])
const redactedConfig = ref<JsonObject>({})
const settings = ref<JsonObject>({})
const uiPreferences = ref({
  launch_at_logon: false,
  close_to_tray: true,
  minimize_to_tray: false,
  update_notifications: true,
})
const logSource = ref<'service' | 'sing-box'>('service')
const logs = ref<string[]>([])
const logFilter = ref('')
const routeFilter = ref('')
const routePeriod = ref<'today' | '7d' | 'all'>('today')
const routeUrl = ref('https://www.gstatic.com/generate_204')
const routeResult = ref<JsonObject | null>(null)
const configJsonMode = ref(false)
const enrollmentLink = ref('')
const enrollmentServer = ref('')
const enrollmentCode = ref('')
const enrollmentPreview = ref<{ server: string; code: string } | null>(null)
const errorMessage = ref('')
const toast = ref('')
const busy = ref('')
const serviceAvailable = ref(true)
const proxyTesting = ref(false)
const theme = ref(localStorage.getItem('sb-easy-theme') || 'system')
let pollTimer = 0
let polling = false
let removeActivation: (() => void) | undefined

const running = computed(() => status.value.running === true)
const telemetry = computed(() => status.value.telemetry || {})
const visibleLogs = computed(() => {
  const query = logFilter.value.trim().toLowerCase()
  return query ? logs.value.filter((line) => line.toLowerCase().includes(query)) : logs.value
})
const visibleRoutes = computed(() => {
  const query = routeFilter.value.trim().toLowerCase()
  return query
    ? routes.value.filter((row) => JSON.stringify(row).toLowerCase().includes(query))
    : routes.value
})
const currentProxy = computed(() => {
  for (const group of proxies.value) {
    if (group?.now) return `${group.tag || group.name} · ${group.now}`
    if (group?.default) return group.tag
  }
  return '未识别'
})
const selectorGroups = computed(() => {
  if (proxies.value.some((item) => Array.isArray(item?.all))) return proxies.value
  return proxies.value.length
    ? [{ tag: '可用出站', type: 'Runtime', now: currentProxy.value, all: proxies.value.map((item) => item.tag), delays: {} }]
    : []
})
const configSections = computed(() => {
  const config = redactedConfig.value || {}
  const tun = Array.isArray(config.inbounds)
    ? config.inbounds.filter((item: any) => item?.type === 'tun')
    : []
  return [
    { title: 'TUN 入口', count: tun.length, data: tun },
    { title: 'DNS 服务器', count: config.dns?.servers?.length || 0, data: config.dns?.servers || [] },
    { title: '路由规则', count: config.route?.rules?.length || 0, data: config.route?.rules || [] },
    { title: '规则集', count: config.route?.rule_set?.length || 0, data: config.route?.rule_set || [] },
    { title: '出站', count: config.outbounds?.length || 0, data: config.outbounds || [] },
  ]
})

function flash(message: string) {
  toast.value = message
  window.setTimeout(() => {
    if (toast.value === message) toast.value = ''
  }, 3_000)
}

function showError(error: unknown) {
  errorMessage.value = error instanceof Error ? error.message : String(error)
}

async function operation(name: string, action: () => Promise<void>) {
  if (busy.value) return
  busy.value = name
  errorMessage.value = ''
  try {
    await action()
  } catch (error) {
    showError(error)
  } finally {
    busy.value = ''
  }
}

async function loadEnrollment() {
  enrollment.value = await rpc<Enrollment>('enrollment.status')
  if (enrollment.value.server && !enrollmentServer.value) enrollmentServer.value = enrollment.value.server
}

async function pollStatus() {
  if (polling) return
  polling = true
  try {
    await loadEnrollment()
    if (enrollment.value.enrolled) {
      status.value = await rpc<JsonObject>('status.get')
      if (running.value && (page.value === 'dashboard' || page.value === 'proxies')) {
        proxies.value = await rpc<any[]>('proxies.list')
      }
      serviceAvailable.value = true
    }
  } catch (error) {
    serviceAvailable.value = false
    if (!status.value.service) showError(error)
  } finally {
    polling = false
  }
}

async function selectPage(next: Page) {
  page.value = next
  if (!enrollment.value.enrolled) return
  try {
    if (next === 'proxies') proxies.value = await rpc<any[]>('proxies.list')
    if (next === 'routing') await loadRoutes()
    if (next === 'config') redactedConfig.value = await rpc<JsonObject>('config.redacted')
    if (next === 'logs') await loadLogs()
    if (next === 'settings') await loadSettings()
  } catch (error) {
    showError(error)
  }
}

async function loadSettings() {
  const [serviceSettings, preferences] = await Promise.all([
    rpc<JsonObject>('settings.get'),
    rpc<typeof uiPreferences.value>('host.preferences'),
  ])
  settings.value = serviceSettings
  uiPreferences.value = preferences
}

async function vpnAction(action: 'start' | 'stop' | 'restart') {
  await operation(action, async () => {
    await rpc(`vpn.${action}`)
    flash(action === 'stop' ? '正在断开' : action === 'restart' ? '正在重启核心' : '正在连接')
    await pollStatus()
  })
}

async function refreshConfig() {
  await operation('refresh', async () => {
    await rpc('config.refresh')
    flash('已请求立即同步配置')
  })
}

function parseEnrollment(raw = enrollmentLink.value) {
  const cleaned = raw.replaceAll('\0', '').trim().replace(/^URL:/i, '').trim().replace(/^['"]|['"]$/g, '')
  const uri = new URL(cleaned)
  if (uri.protocol.toLowerCase() !== 'sbeasy:' || uri.hostname.toLowerCase() !== 'enroll') {
    throw new Error('不是有效的 sb-easy 注册链接')
  }
  const rawServer = uri.searchParams.get('server') || ''
  const code = uri.searchParams.get('code') || ''
  const server = new URL(rawServer)
  if (!['http:', 'https:'].includes(server.protocol) || server.username || server.password || server.pathname !== '/' || server.search || server.hash) {
    throw new Error('服务器必须是 HTTP(S) origin，不能包含路径或凭据')
  }
  if (!/^[0-9a-f]{64}$/i.test(code)) throw new Error('注册码必须是 64 位十六进制字符')
  enrollmentPreview.value = { server: server.origin, code: code.toLowerCase() }
  enrollmentServer.value = server.origin
  enrollmentCode.value = code.toLowerCase()
  enrollmentLink.value = ''
}

function previewManualEnrollment() {
  const server = new URL(enrollmentServer.value.trim())
  if (!['http:', 'https:'].includes(server.protocol) || server.username || server.password || server.pathname !== '/' || server.search || server.hash) {
    throw new Error('服务器必须是 HTTP(S) origin')
  }
  const code = enrollmentCode.value.trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(code)) throw new Error('注册码必须是 64 位十六进制字符')
  enrollmentPreview.value = { server: server.origin, code }
}

function previewEnrollmentSafely() {
  errorMessage.value = ''
  try {
    if (enrollmentLink.value.trim()) parseEnrollment()
    else previewManualEnrollment()
  } catch (error) {
    showError(error)
  }
}

async function applyEnrollment() {
  if (!enrollmentPreview.value) return
  await operation('enroll', async () => {
    enrollment.value = await rpc<Enrollment>('enrollment.apply', enrollmentPreview.value!)
    enrollmentCode.value = ''
    enrollmentPreview.value = null
    status.value = await rpc<JsonObject>('status.get')
    flash('设备注册成功')
  })
}

async function forgetEnrollment() {
  if (!window.confirm('确定忘记这台设备？本机凭据和生成配置将被删除，VPN 会断开。')) return
  await operation('forget', async () => {
    await rpc('enrollment.forget')
    enrollment.value = { enrolled: false }
    status.value = {}
    page.value = 'dashboard'
    flash('已清除本机注册信息')
  })
}

async function decodeQrBlob(blob: Blob) {
  if (blob.size > 12 * 1024 * 1024) throw new Error('二维码图片不能超过 12 MiB')
  const bitmap = await createImageBitmap(blob)
  try {
    if (!bitmap.width || !bitmap.height || bitmap.width > 8192 || bitmap.height > 8192) {
      throw new Error('二维码图片尺寸无效或过大')
    }
    const scale = Math.min(1, 2048 / Math.max(bitmap.width, bitmap.height))
    const width = Math.max(1, Math.round(bitmap.width * scale))
    const height = Math.max(1, Math.round(bitmap.height * scale))
    const canvas = document.createElement('canvas')
    canvas.width = width
    canvas.height = height
    const context = canvas.getContext('2d', { willReadFrequently: true })
    if (!context) throw new Error('无法读取二维码图片')
    context.drawImage(bitmap, 0, 0, width, height)
    const image = context.getImageData(0, 0, width, height)
    const result = jsQR(image.data, width, height, { inversionAttempts: 'attemptBoth' })
    if (!result?.data) throw new Error('图片中没有可识别的二维码')
    parseEnrollment(result.data)
  } finally {
    bitmap.close()
  }
}

async function chooseQr(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  await operation('qr-file', async () => decodeQrBlob(file))
}

async function pasteQr() {
  await operation('qr-clipboard', async () => {
    const items = await navigator.clipboard.read()
    for (const item of items) {
      const type = item.types.find((value) => value.startsWith('image/'))
      if (type) {
        await decodeQrBlob(await item.getType(type))
        return
      }
    }
    throw new Error('剪贴板中没有图片')
  })
}

async function selectProxy(group: string, proxy: string) {
  await operation(`proxy-${group}`, async () => {
    await rpc('proxy.select', { group, proxy })
    proxies.value = await rpc<any[]>('proxies.list')
    flash(`已切换到 ${proxy}`)
  })
}

async function testProxies(group?: any) {
  proxyTesting.value = true
  errorMessage.value = ''
  try {
    const tags = group?.all || undefined
    await rpc('proxies.test', tags ? { tags } : {})
    proxies.value = await rpc<any[]>('proxies.list')
    flash('节点测速完成')
  } catch (error) {
    showError(error)
  } finally {
    proxyTesting.value = false
  }
}

async function loadRoutes() {
  const result = await rpc<JsonObject>('routes.stats', { period: routePeriod.value })
  routes.value = Array.isArray(result?.rows) ? result.rows : []
}

async function testRoute() {
  await operation('route-test', async () => {
    const parsed = new URL(routeUrl.value.trim())
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('只支持 HTTP/HTTPS URL')
    routeResult.value = await rpc<JsonObject>('route.test', { url: parsed.toString() })
  })
}

async function loadLogs() {
  const result = await rpc<JsonObject>('logs.tail', { source: logSource.value, lines: 1000 })
  logs.value = Array.isArray(result?.lines) ? result.lines : []
}

async function clearLogs() {
  if (!window.confirm(`确定清空${logSource.value === 'service' ? '服务' : '核心'}日志？`)) return
  await operation('clear-logs', async () => {
    await rpc('logs.clear', { source: logSource.value })
    await loadLogs()
    flash('日志已清空')
  })
}

async function uploadLogs() {
  await operation('upload-logs', async () => {
    const result = await rpc<JsonObject>('logs.upload')
    flash(`诊断已上传：${result.report_id || '已接收'}`)
  })
}

async function copyLogs() {
  await navigator.clipboard.writeText(visibleLogs.value.join('\r\n'))
  flash('已复制筛选后的日志')
}

async function exportLogs() {
  await operation('export-logs', async () => {
    const result = await rpc<JsonObject>('host.exportLogs')
    if (!result.cancelled) flash(`日志已导出：${result.file || '完成'}`)
  })
}

async function saveSettings() {
  await operation('settings', async () => {
    const [serviceSettings, preferences] = await Promise.all([
      rpc<JsonObject>('settings.update', { settings: settings.value }),
      rpc<typeof uiPreferences.value>('host.preferences.update', { preferences: uiPreferences.value }),
    ])
    settings.value = serviceSettings
    uiPreferences.value = preferences
    flash('设置已保存，配置同步已排队')
  })
}

async function openReleases() {
  await rpc('host.openExternal', { url: 'https://github.com/cloudy064/sb-easy/releases' })
}

function setTheme(value: string) {
  theme.value = value
  localStorage.setItem('sb-easy-theme', value)
}

watch(theme, (value) => {
  document.documentElement.dataset.theme = value
}, { immediate: true })
watch(logSource, () => {
  if (page.value === 'logs') loadLogs().catch(showError)
})
watch(routePeriod, () => {
  if (page.value === 'routing') loadRoutes().catch(showError)
})

onMounted(async () => {
  removeActivation = onEnrollmentActivation((activation) => {
    enrollmentServer.value = activation.server
    enrollmentCode.value = activation.code
    enrollmentPreview.value = activation
    page.value = 'dashboard'
  })
  try {
    await rpc('host.ready')
    await pollStatus()
  } catch (error) {
    serviceAvailable.value = false
    showError(error)
  }
  pollTimer = window.setInterval(pollStatus, 2_000)
})

onBeforeUnmount(() => {
  window.clearInterval(pollTimer)
  removeActivation?.()
})
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand"><span class="brand-mark">S</span><div><b>sb-easy</b><small>Windows Client</small></div></div>
      <nav aria-label="主导航">
        <button v-for="item in pages" :key="item.id" :class="{ active: page === item.id }" :disabled="!enrollment.enrolled && item.id !== 'dashboard'" @click="selectPage(item.id)">
          <span class="nav-mark">{{ item.mark }}</span>{{ item.label }}
        </button>
      </nav>
      <div class="sidebar-status">
        <span class="status-dot" :class="{ online: serviceAvailable, running }"></span>
        <div><b>{{ serviceAvailable ? (running ? '已连接' : '服务在线') : '服务不可用' }}</b><small>{{ enrollment.profile?.name || '尚未注册' }}</small></div>
      </div>
    </aside>

    <main class="workspace">
      <header class="topbar">
        <div><h1>{{ pages.find((item) => item.id === page)?.label }}</h1><p>{{ enrollment.host_name || enrollment.host_id || '本机 Windows 客户端' }}</p></div>
        <button class="icon-button" title="同步配置" :disabled="!enrollment.enrolled || !!busy" @click="refreshConfig">↻</button>
      </header>

      <div v-if="errorMessage" class="alert" role="alert"><span>{{ errorMessage }}</span><button @click="errorMessage = ''">×</button></div>
      <div v-if="toast" class="toast" role="status">{{ toast }}</div>

      <section v-if="!enrollment.enrolled" class="enrollment-layout">
        <div class="welcome-card">
          <span class="eyebrow">首次使用</span><h2>将这台 Windows 设备加入 sb-easy</h2>
          <p>注册链接和一次性注册码只用于预览与本次兑换，不会写入 UI 配置或日志。</p>
          <ol><li>在管理端打开“设备”并创建注册码</li><li>粘贴注册链接，或扫描二维码图片</li><li>核对服务器地址后确认注册</li></ol>
        </div>
        <div class="card enrollment-card">
          <label>注册链接<input v-model="enrollmentLink" autocomplete="off" placeholder="sbeasy://enroll?..." /></label>
          <div class="or"><span>或者手动输入</span></div>
          <label>服务器 origin<input v-model="enrollmentServer" inputmode="url" autocomplete="off" placeholder="https://panel.example.com" /></label>
          <label>一次性注册码<input v-model="enrollmentCode" class="code-input" autocomplete="off" maxlength="64" placeholder="64 位十六进制字符" /></label>
          <div class="button-row wrap">
            <button class="primary" @click="previewEnrollmentSafely">预览注册</button>
            <button @click="pasteQr">从剪贴板识别二维码</button>
            <label class="button file-button">选择二维码图片<input type="file" accept="image/*" @change="chooseQr" /></label>
          </div>
          <div v-if="enrollmentPreview" class="preview">
            <span class="eyebrow">请核对</span><b>{{ enrollmentPreview.server }}</b><small>注册码 ·•••• {{ enrollmentPreview.code.slice(-8) }}</small>
            <button class="primary wide" :disabled="busy === 'enroll'" @click="applyEnrollment">{{ busy === 'enroll' ? '正在注册…' : '确认并注册' }}</button>
          </div>
        </div>
      </section>

      <template v-else>
        <section v-if="page === 'dashboard'" class="dashboard-grid">
          <article class="connection-card" :class="{ active: running }">
            <div class="connection-copy"><span class="eyebrow">{{ running ? '隧道正在运行' : '隧道已停止' }}</span><h2>{{ running ? '网络已受保护' : '准备连接' }}</h2><p>{{ status.last_error || (running ? '流量正由当前 Profile 管理' : '连接后将应用中心下发的路由策略') }}</p></div>
            <button class="power" :class="{ active: running }" :aria-label="running ? '断开连接' : '连接'" @click="vpnAction(running ? 'stop' : 'start')"><span>⌁</span></button>
            <div class="connection-actions"><button v-if="running" @click="vpnAction('restart')">重启核心</button><button @click="refreshConfig">立即同步</button></div>
          </article>
          <article class="card profile-card"><span class="eyebrow">当前 Profile</span><h3>{{ enrollment.profile?.name || '未命名' }}</h3><dl><div><dt>规则来源</dt><dd><span v-if="status.rule_source === 'quickjs'" class="badge violet">QuickJS</span><span v-else class="badge">Profile</span></dd></div><div><dt>配置版本</dt><dd class="mono">{{ status.etag || '尚未同步' }}</dd></div><div><dt>最近同步</dt><dd>{{ status.last_cycle || '等待服务周期' }}</dd></div></dl></article>
          <article class="card traffic-card"><span class="eyebrow">实时流量</span><div class="rates"><div><small>↑ 上传</small><b>{{ formatRate(telemetry.up) }}</b></div><div><small>↓ 下载</small><b>{{ formatRate(telemetry.down) }}</b></div></div><div class="totals"><span>累计上传 {{ formatBytes(telemetry.up_total) }}</span><span>累计下载 {{ formatBytes(telemetry.down_total) }}</span><span>{{ telemetry.conn_count || 0 }} 条连接</span></div></article>
          <article class="card proxy-card"><span class="eyebrow">当前代理</span><h3>{{ currentProxy }}</h3><p>进入代理页可查看策略组、切换节点并运行渐进测速。</p><button @click="selectPage('proxies')">管理代理</button></article>
          <article class="card details-card"><span class="eyebrow">运行信息</span><dl><div><dt>服务版本</dt><dd>{{ status.version || '—' }}</dd></div><div><dt>sing-box</dt><dd>{{ status.singbox_version || '1.13.12' }}</dd></div><div><dt>设备</dt><dd>{{ status.device?.hostname || enrollment.host_name || 'Windows' }}</dd></div><div><dt>连接目标</dt><dd class="truncate">{{ enrollment.server }}</dd></div></dl></article>
        </section>

        <section v-else-if="page === 'proxies'" class="page-stack">
          <div class="section-heading"><div><h2>策略组与节点</h2><p>展示运行核心确认的选择；切换成功后会重新读取当前值。</p></div><button class="primary" :disabled="proxyTesting" @click="testProxies()">{{ proxyTesting ? '正在测速…' : '全部测速' }}</button></div>
          <div v-if="!selectorGroups.length" class="empty card">当前配置没有可用策略组。</div>
          <article v-for="group in selectorGroups" :key="group.tag || group.name" class="card proxy-group">
            <header><div><span class="badge">{{ group.type || 'Selector' }}</span><h3>{{ group.tag || group.name }}</h3><p>当前：<b>{{ group.now || '自动选择' }}</b></p></div><button :disabled="proxyTesting" @click="testProxies(group)">测速此组</button></header>
            <div class="node-grid"><button v-for="node in group.all" :key="node" class="node" :class="{ selected: node === group.now }" :disabled="busy === `proxy-${group.tag || group.name}`" @click="selectProxy(group.tag || group.name, node)"><span class="node-radio"></span><b>{{ node }}</b><small :class="latencyClass(group.delays?.[node])">{{ latencyText(group.delays?.[node]) }}</small></button></div>
          </article>
        </section>

        <section v-else-if="page === 'routing'" class="page-stack">
          <article class="card route-test"><div class="section-heading"><div><h2>实际 URL 路由测试</h2><p>由 Service 发起真实 HTTP/HTTPS 连接并与 sing-box 连接事件关联。</p></div></div><div class="inline-form"><input v-model="routeUrl" inputmode="url" placeholder="https://example.com/" @keyup.enter="testRoute" /><button class="primary" :disabled="busy === 'route-test'" @click="testRoute">{{ busy === 'route-test' ? '测试中…' : '测试走向' }}</button></div><div v-if="routeResult" class="route-result"><span class="route-kind">{{ routeResult.kind || (routeResult.available === false ? '暂不可用' : '已完成') }}</span><b>{{ routeResult.outbound || routeResult.reason || routeResult.url }}</b><div v-if="routeResult.chain || routeResult.chains" class="chain"><span v-for="item in (routeResult.chain || routeResult.chains)" :key="item">{{ item }}</span></div><small v-if="routeResult.rule">命中规则：{{ routeResult.rule }}</small></div></article>
          <div class="section-heading"><div><h2>本地域名统计</h2><p>仅保存在本机，原始连接历史不会自动上传。</p></div><div class="segmented"><button v-for="item in [{id:'today',label:'今天'},{id:'7d',label:'7 天'},{id:'all',label:'全部'}]" :key="item.id" :class="{ active: routePeriod === item.id }" @click="routePeriod = item.id as any">{{ item.label }}</button></div></div>
          <div class="filter-row"><input v-model="routeFilter" type="search" placeholder="搜索域名、出站或规则" /><span>{{ visibleRoutes.length }} 条</span></div>
          <div class="card table-card"><table><thead><tr><th>域名</th><th>结果</th><th>出站链</th><th>连接</th><th>下行</th><th>最近</th></tr></thead><tbody><tr v-for="row in visibleRoutes" :key="`${row.domain}-${row.outbound}-${row.last_seen}`"><td><b>{{ row.domain }}</b></td><td><span class="badge">{{ row.kind || row.outbound_type || 'proxy' }}</span></td><td>{{ [row.outbound, ...(row.chain || [])].filter(Boolean).join(' → ') }}</td><td>{{ row.connection_count || 0 }}</td><td>{{ formatBytes(row.downlink_total) }}</td><td>{{ formatTime(row.last_seen) }}</td></tr><tr v-if="!visibleRoutes.length"><td colspan="6" class="empty">尚无持久化路由统计。</td></tr></tbody></table></div>
        </section>

        <section v-else-if="page === 'config'" class="page-stack">
          <div class="section-heading"><div><h2>生效配置</h2><p>只读显示 Service 返回的脱敏配置，不提供本地策略编辑。</p></div><div class="segmented"><button :class="{ active: !configJsonMode }" @click="configJsonMode = false">可读视图</button><button :class="{ active: configJsonMode }" @click="configJsonMode = true">脱敏 JSON</button></div></div>
          <div v-if="status.rule_source === 'quickjs'" class="quickjs-note"><span class="badge violet">QuickJS</span><div><b>路由规则由服务端 QuickJS 生成</b><p>下面显示的是脚本执行后实际交给 sing-box 的结果。</p></div></div>
          <pre v-if="configJsonMode" class="card json-view">{{ JSON.stringify(redactedConfig, null, 2) }}</pre>
          <div v-else class="config-grid"><article v-for="section in configSections" :key="section.title" class="card config-section"><header><h3>{{ section.title }}</h3><span>{{ section.count }}</span></header><div v-if="section.data.length" class="config-items"><div v-for="(item, index) in section.data.slice(0, 80)" :key="item.tag || index"><b>{{ item.tag || item.type || `项目 ${index + 1}` }}</b><small>{{ summarize(item) }}</small></div></div><p v-else class="empty">没有相关项目</p></article></div>
        </section>

        <section v-else-if="page === 'logs'" class="page-stack logs-page">
          <div class="section-heading"><div><h2>本机诊断日志</h2><p>读取前由 Service 脱敏；上传只能由用户显式触发。</p></div><div class="button-row"><button @click="copyLogs">复制</button><button @click="exportLogs">导出</button><button @click="clearLogs">清空</button><button class="primary" @click="uploadLogs">上传诊断</button></div></div>
          <div class="log-toolbar"><div class="segmented"><button :class="{ active: logSource === 'service' }" @click="logSource = 'service'">服务</button><button :class="{ active: logSource === 'sing-box' }" @click="logSource = 'sing-box'">sing-box</button></div><input v-model="logFilter" type="search" placeholder="筛选级别或文本" /><button @click="loadLogs">刷新</button><span>{{ visibleLogs.length }} 行</span></div>
          <div class="log-view card"><div v-for="(line, index) in visibleLogs" :key="index" class="log-line"><span>{{ String(index + 1).padStart(4, '0') }}</span><code>{{ line }}</code></div><p v-if="!visibleLogs.length" class="empty">暂无日志</p></div>
        </section>

        <section v-else class="settings-grid">
          <article class="card settings-card"><h2>运行设置</h2><p>设置由 Service 持久化；更改后会触发受控配置刷新。</p><label class="switch-row"><span><b>开机自动连接</b><small>无需用户登录，由 Windows Service 在启动后恢复连接</small></span><input v-model="settings.connect_at_boot" type="checkbox" /></label><label class="switch-row"><span><b>局域网兼容</b><small>保留本地组播与设备发现的直连规则；不会覆盖中心策略</small></span><input v-model="settings.lan_compatibility" type="checkbox" /></label><label class="switch-row"><span><b>严格 DNS 防泄漏</b><small>启用 TUN strict_route；可能影响 VirtualBox 等多宿主网络软件</small></span><input v-model="settings.strict_dns" type="checkbox" /></label><label><span>默认代理出站</span><input v-model="settings.default_proxy_outbound" placeholder="留空则使用 Profile 默认值" /></label><label><span>服务日志保留</span><select v-model.number="settings.log_retention_files"><option :value="1">1 个轮转文件</option><option :value="3">3 个轮转文件（推荐）</option><option :value="5">5 个轮转文件</option><option :value="10">10 个轮转文件</option></select></label><button class="primary" @click="saveSettings">保存全部设置</button></article>
          <article class="card settings-card"><h2>界面设置</h2><p>这些非敏感偏好保存在当前用户的 HKCU；不会授予 Service 权限。</p><label><span>主题</span><select :value="theme" @change="setTheme(($event.target as HTMLSelectElement).value)"><option value="system">跟随 Windows</option><option value="light">浅色</option><option value="dark">深色</option></select></label><label class="switch-row"><span><b>登录后启动界面</b><small>仅为当前 Windows 用户启动托盘界面，不影响开机自动连接</small></span><input v-model="uiPreferences.launch_at_logon" type="checkbox" /></label><label class="switch-row"><span><b>关闭到托盘</b><small>关闭窗口不会断开 VPN；退出界面是单独操作</small></span><input v-model="uiPreferences.close_to_tray" type="checkbox" /></label><label class="switch-row"><span><b>最小化到托盘</b><small>最小化窗口时隐藏任务栏按钮</small></span><input v-model="uiPreferences.minimize_to_tray" type="checkbox" /></label><button @click="rpc('host.exit')">退出界面</button></article>
          <article class="card settings-card"><h2>更新</h2><p>首版不执行无人值守更新；安装与签名链由 W4 处理。</p><label class="switch-row"><span><b>接收更新通知</b><small>记录当前用户的通知偏好；开发构建可手动查看官方发布页</small></span><input v-model="uiPreferences.update_notifications" type="checkbox" /></label><button @click="openReleases">打开 GitHub Releases</button></article>
          <article class="card settings-card device-card"><h2>设备信息</h2><dl><div><dt>名称</dt><dd>{{ enrollment.host_name || '—' }}</dd></div><div><dt>设备 ID</dt><dd class="mono">{{ enrollment.host_id }}</dd></div><div><dt>控制面</dt><dd>{{ enrollment.server }}</dd></div><div><dt>架构</dt><dd>{{ status.device?.architecture || 'x86_64' }}</dd></div></dl><button class="danger" @click="forgetEnrollment">忘记并重新注册</button></article>
        </section>
      </template>
    </main>
  </div>
</template>

<script lang="ts">
export default {
  methods: {
    formatBytes(value: unknown) {
      const bytes = Math.max(0, Number(value) || 0)
      const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
      let amount = bytes
      let unit = 0
      while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++ }
      return `${amount < 10 && unit ? amount.toFixed(1) : Math.round(amount)} ${units[unit]}`
    },
    formatRate(value: unknown) { return `${this.formatBytes(value)}/s` },
    formatTime(value: unknown) { const time = Number(value); return time > 0 ? new Date(time).toLocaleString() : '—' },
    latencyText(value: unknown) { const delay = Number(value); return delay > 0 ? `${delay} ms` : '未测速' },
    latencyClass(value: unknown) { const delay = Number(value); return delay > 800 ? 'bad' : delay > 300 ? 'warn' : delay > 0 ? 'good' : '' },
    summarize(item: Record<string, unknown>) {
      return Object.entries(item).filter(([key, value]) => !['tag', 'type'].includes(key) && ['string', 'number', 'boolean'].includes(typeof value)).slice(0, 4).map(([key, value]) => `${key}: ${value}`).join(' · ') || item.type || '已配置'
    },
  },
}
</script>
