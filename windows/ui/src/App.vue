<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import AppIcon from './components/AppIcon.vue'
import SubscriptionsPanel from './components/SubscriptionsPanel.vue'
import { parseSubscription } from './lib/subscriptions'
import ServiceRouting from './components/ServiceRouting.vue'
import ExtensionView from './components/ExtensionView.vue'
import ExtensionsPanel from './components/ExtensionsPanel.vue'
import NetworkToolsView from './components/NetworkToolsView.vue'
import LogsView from './components/LogsView.vue'
import type { ExtensionId, ExtensionInfo } from './lib/protocol'
import { bytes, rates, shortVersion, nodeKind } from './lib/dashboard'
import brandMark from '../../../assets/branding/sb-easy-mark-v2.svg'
import { BridgeError, findNativeTransport, NativeBridge } from './lib/bridge'
import { previewEnrollment } from './lib/enrollment'
import { configStage } from './lib/config'
import { connectionActions, runtimeDetail } from './lib/connection'
import type { ConfigSummary, EnrollmentResult, HelloResult, Method, StatusResult, ConfigInspection, RuntimeSnapshot } from './lib/protocol'

type ConnectionState = 'checking' | 'online' | 'offline' | 'host_missing'
const bridge = new NativeBridge(findNativeTransport())
type Page = 'connections' | 'logs' | 'rules' | 'extensions' | 'capture' | 'statistics' | 'network-tools' | 'overview' | 'proxies' | 'profiles' | 'activity' | 'settings' | 'diagnostics'
const page = ref<Page>('overview')
const toolsOpen = ref(false)
const extensions = ref<ExtensionInfo[]>([])
const enabledExtensions = computed(() => extensions.value.filter(e => e.installed && e.enabled && e.id !== 'network-tools'))
const extensionPage = computed(() => enabledExtensions.value.find(e => e.id === page.value))
const captureEnabled = computed(() => enabledExtensions.value.some(e => e.id === 'capture'))
function openExtension(id: ExtensionId){selectPage(id === 'network-tools' ? 'connections' : id)}
watch(extensions, () => { if (['capture','statistics','network-tools'].includes(page.value) && !extensionPage.value) page.value = 'extensions' })
const navigation: { id: Page; label: string; description: string }[] = [
  { id: 'extensions', label: '扩展商店', description: '按需安装高级功能，让基础代理保持简单。' },
  { id: 'overview', label: '连接', description: '连接网络，为每项服务选择出口。' },
  { id: 'proxies', label: '节点与订阅', description: '按来源管理节点，添加只在本机使用的订阅。' },
  { id: 'connections', label: '活动连接', description: '查看当前连接、应用和实际出口。' },
  { id: 'logs', label: '运行日志', description: '查看内核运行日志，排查连接问题。' },
  { id: 'rules', label: '规则详情', description: '查看当前生效和已下载的分流规则。' },
  { id: 'statistics', label: '流量统计', description: '按应用、域名与 host 查看累计流量和出站记录。' },
  { id: 'capture', label: '流量采集', description: '按应用、域名与 BPF 筛选，保存和管理 PCAP 文件。' },
  { id: 'profiles', label: '配置管理', description: '同步、校验并管理此设备的服务端配置。' },
  { id: 'activity', label: '活动记录', description: '查看本次打开界面后的连接与操作记录。' },
]
const currentPage = computed(() => navigation.find(item => item.id === page.value) ??
  { label: page.value === 'settings' ? '设置' : '连接诊断', description: '管理外观、状态刷新和设备信息。' })
const inspection = ref<ConfigInspection | null>(null)
const catalogIssue = ref('')
const runtime = ref<RuntimeSnapshot | null>(null)
const runtimeIssue = ref('')
const telemetryBusy = ref(false)
const catalogSource = ref<'active' | 'candidate'>('active')
const search = ref('')
const pendingRouting = ref('')
const routingNodes = computed(() => ((config.value?.routing_live ? inspection.value?.active : inspection.value?.candidate)?.nodes ?? []).filter(node => node.type !== 'block' && !node.tag.startsWith('sb-easy-local-')).map(node => ({ ...node, label: nodeLabel(node.tag), source: sourceMap.value.get(node.tag)?.name })))
const routingGroups = computed(() => config.value?.routing_groups ?? [])
const sourceFilter = ref('')
const subscriptionSummary = computed(() => config.value?.subscriptions)
const sourceMap = computed(() => {
  const map = new Map<string, { key: string; name: string }>()
  for (const scope of ['managed', 'local'] as const) for (const sub of subscriptionSummary.value?.[scope] ?? [])
    for (const tag of sub.tags) map.set(tag, { key: `${scope}:${sub.id}`, name: sub.name })
  return map
})
function nodeLabel(tag: string): string { return tag.replace(/^local-[a-f0-9-]{36}\//, '') }
const nodeFilter = ref('all')
const theme = ref<'system' | 'light' | 'dark'>('system')
const autoRefresh = ref(true)
const ipv6Network = computed(() => {
  const v = status.value?.ipv6
  if (!v?.checked) return '尚未检测'
  if (v.native_route) return '具备联网条件，未实测'
  return v.global_address ? '有公网地址，缺少默认路由' : '未发现公网 IPv6'
})
const ipv6Tunnel = computed(() => {
  if (!status.value?.ipv6?.checked) return '尚未检测'
  if (!status.value.core_running) return '连接未启动'
  return status.value.ipv6.tun_route ? '已检测到 IPv6 接管路由' : '未检测到 IPv6 接管路由'
})
const speed = ref<{ up: number; down: number } | null>(null)
const activities = ref<{ id: number; time: string; title: string; detail: string; failed: boolean }[]>([])
let activityId = 0
let telemetryTimer: ReturnType<typeof setTimeout> | undefined
let previousSample: RuntimeSnapshot | null = null
const catalog = computed(() => catalogSource.value === 'active' ? inspection.value?.active : inspection.value?.candidate)
const displayNodes = computed(() => (catalogSource.value === 'active' && runtime.value ? runtime.value.nodes : catalog.value?.nodes ?? []).filter(node => !node.tag.startsWith('sb-easy-local-')))
const groups = computed(() => displayNodes.value.filter(item => item.member_count > 0))
const filteredNodes = computed(() => displayNodes.value.filter(item =>
  (!sourceFilter.value || (sourceMap.value.get(item.tag)?.key ?? 'unknown') === sourceFilter.value) &&
  (nodeFilter.value === 'all' || (nodeFilter.value === 'groups' ? item.member_count > 0 : item.member_count === 0)) &&
  `${item.tag} ${item.type} ${item.selected}`.toLowerCase().includes(search.value.toLowerCase())))
const runningCatalog = computed(() => inspection.value?.active ?? inspection.value?.candidate)
const proxyEndpoint = computed(() => runningCatalog.value?.inbounds.find(item => ['mixed', 'socks', 'http'].includes(item.type)))
const trafficReady = computed(() => status.value?.core_running && runtime.value?.running && !runtimeIssue.value)
const sourceLabel = computed(() => catalogSource.value === 'active' ? '当前运行配置' : '已下载候选配置')
function selectPage(value: Page): void {
  page.value = value
  if (['profiles', 'rules', 'activity'].includes(value)) toolsOpen.value = true
  search.value = ''
  window.scrollTo({ top: 0 })
}
function record(title: string, detail: string, failed = false): void {
  activities.value.unshift({ id: ++activityId, time: new Date().toLocaleTimeString('zh-CN', { hour12: false }), title, detail, failed })
  activities.value = activities.value.slice(0, 100)
}
watch([theme, autoRefresh], () => {
  document.documentElement.dataset.theme = theme.value
  try { localStorage.setItem('sb-easy-display', JSON.stringify({ theme: theme.value, autoRefresh: autoRefresh.value })) } catch { /* Settings still apply for this window. */ }
})
async function readTelemetry(): Promise<void> {
  if (destroyed || telemetryBusy.value || locked.value || !status.value?.core_running || !supports('runtime.snapshot')) return
  telemetryBusy.value = true
  const etag = status.value.config?.active_etag
  try {
    const sample = await bridge.request('runtime.snapshot', {}, { timeoutMs: 6_000 })
    if (destroyed || locked.value || !status.value?.core_running || status.value.config?.active_etag !== etag || sample.etag !== etag) return
    speed.value = rates(previousSample, sample)
    previousSample = sample
    runtime.value = sample
    runtimeIssue.value = ''
  } catch (error) {
    if (!destroyed) { runtime.value = null; speed.value = null; previousSample = null; runtimeIssue.value = errorMessage(error) }
  } finally { telemetryBusy.value = false }
}
async function pollTelemetry(): Promise<void> {
  if (destroyed) return
  if (autoRefresh.value && document.visibilityState === 'visible') await readTelemetry()
  if (!destroyed) telemetryTimer = setTimeout(() => void pollTelemetry(), 2_000)
}

const connection = ref<ConnectionState>(bridge.available ? 'checking' : 'host_missing')
const busy = ref(false)
const hello = ref<HelloResult | null>(null)
const enrollment = ref<EnrollmentResult | null>(null)
const status = ref<StatusResult | null>(null)
const issue = ref<BridgeError | null>(null)
const checkedAt = ref<Date | null>(null)
const config = ref<ConfigSummary | null>(null)
const configIssue = ref('')
const operation = ref<'subscription' | 'service' | 'routing' | 'enroll' | 'forget' | 'sync' | 'validate' | 'start' | 'stop' | null>(null)
const enrollmentUri = ref('')
const confirmForget = ref(false)
const actionNotice = ref('')
const actionFailed = ref(false)
const locked = computed(() => busy.value || operation.value !== null)
const deviceStateError = computed(() => status.value?.error ?? enrollment.value?.error ?? null)
const enrollmentPreview = computed(() => {
  if (!enrollmentUri.value.trim()) return { preview: null, error: '' }
  try { return { preview: previewEnrollment(enrollmentUri.value), error: '' } }
  catch (error) { return { preview: null, error: error instanceof Error ? error.message : '注册链接无效' } }
})
let destroyed = false
let refreshTimer: ReturnType<typeof setInterval> | undefined
let runtimeTimer: ReturnType<typeof setTimeout> | undefined
let runtimeGeneration = 0

const phaseLabels: Record<string, string> = {
  UNENROLLED: '等待设备注册', STOPPED: '已断开', STARTING: '正在启动',
  RUNNING: '内核运行中', STOPPING: '正在停止', ROLLING_BACK: '正在恢复配置',
  ERROR: '运行异常', DEGRADED: '需要恢复连接',
}

const stateLabel = computed(() => {
  if (connection.value === 'host_missing') return '原生宿主不可用'
  if (connection.value === 'checking') return '正在检查服务'
  if (connection.value === 'offline') return '服务不可用'
  if (deviceStateError.value) return '本地设备状态不可用'
  if (status.value?.phase === 'RUNNING') return '代理已连接'
  return phaseLabels[status.value?.phase ?? ''] ?? '未知运行状态'
})
const serviceLabel = computed(() => ({
  checking: '正在检查', online: '已连接', offline: '离线', host_missing: '不可用',
})[connection.value])
const stateDetail = computed(() => {
  if (connection.value === 'host_missing') return '当前页面未连接 Windows 原生宿主。请通过 sb-easy 桌面程序打开，浏览器预览无法访问本机服务。'
  if (connection.value === 'checking') return '正在准备本地后台并读取设备状态，首次打开可能需要几秒。'
  if (connection.value === 'offline') return '本地后台暂未就绪。刷新状态会尝试自动恢复，具体原因见下方提示。'
  if (deviceStateError.value) return '本地设备资料无法读取，已有文件保持原样。请先修复存储问题；此时不能重新注册或覆盖设备状态。'
  if (!enrollment.value?.enrolled) return '本机服务已就绪。请在下方粘贴管理面板生成的一次性注册链接，完成此设备的授权。'
  if (status.value?.phase === 'RUNNING') return '代理已就绪。你可以在下方直接切换出口，无需断开连接。'
  return status.value ? runtimeDetail(status.value) : '正在读取本机内核状态。'
})
const checkedTime = computed(() => checkedAt.value?.toLocaleTimeString('zh-CN', { hour12: false }) ?? '尚未检查')
const deviceLabel = computed(() => deviceStateError.value ? '无法读取' : enrollment.value ? enrollment.value.enrolled ? '已注册' : '待注册' : '尚未读取')
const coreLabel = computed(() => status.value ? status.value.core_running ? '运行中' : '未运行' : '尚未读取')
const deviceMetadata = computed(() => enrollment.value ?? status.value)
const configMetadata = computed(() => {
  const summary = config.value ?? status.value?.config ?? enrollment.value?.config
  if (!summary) return null
  // A status poll can clear activation while the candidate summary stays valid.
  const runtime = status.value?.config
  return runtime ? { ...summary, active_etag: runtime.active_etag, last_good_etag: runtime.last_good_etag } : summary
})
const stage = computed(() => configStage(configMetadata.value, status.value))
const controls = computed(() => connectionActions(status.value, configMetadata.value))
const profileName = computed(() => config.value?.profile?.name ?? deviceMetadata.value?.profile?.name ?? '尚未分配')
const supports = (method: Method) => hello.value?.supported_methods.includes(method) === true
const canAct = (method: Method) => connection.value === 'online' && !locked.value && !deviceStateError.value && supports(method)

watch(actionNotice, value => { if (value) record(actionFailed.value ? '操作需要检查' : '操作完成', value, actionFailed.value) })
watch(() => status.value?.phase, (value, old) => {
  if (value && value !== old) record(phaseLabels[value] ?? value, status.value ? runtimeDetail(status.value) : '')
  if (value !== 'RUNNING') {
    runtime.value = null; previousSample = null; speed.value = null; runtimeIssue.value = ''
    if (inspection.value) inspection.value = { ...inspection.value, active: null }
  }
})

function errorMessage(error: unknown): string {
  if (error instanceof BridgeError) {
    const messages: Record<string, string> = { ROUTING_NODE_UNAVAILABLE: '所选节点已从配置移除，请选择其他节点或恢复服务器设置。', ROUTING_UNSUPPORTED: '此分组或 DNS 结构无法安全覆盖，请恢复服务器设置。', LIVE_ROUTING_UNAVAILABLE: '当前内核尚未包含此分组，请先应用新版配置。', LIVE_ROUTING_UNCERTAIN: '切换回滚未能确认，请刷新并检查当前出口。' }
    if (messages[error.code]) return messages[error.code]!
  }
  return error instanceof Error ? error.message : '操作未完成，请刷新状态后检查'
}

async function startService(): Promise<void> {
  if (locked.value || !bridge.available) return
  operation.value = 'service'
  try {
    await bridge.request('service.start', {}, { timeoutMs: 300_000 })
    record('后台服务已启动', '管理员授权完成，正在重新连接后台。')
    issue.value = null
  } catch (error) {
    issue.value = error instanceof BridgeError ? error : new BridgeError('SERVICE_START_FAILED', errorMessage(error))
    record('后台服务未启动', issue.value.message, true)
    return
  } finally { operation.value = null }
  if (!destroyed) await refresh()
}

async function refresh(): Promise<void> {
  if (locked.value) return
  busy.value = true
  issue.value = null
  configIssue.value = ''
  if (connection.value !== 'online') connection.value = bridge.available ? 'checking' : 'host_missing'
  try {
    const greeting = await bridge.request('protocol.hello', {}, { timeoutMs: 20_000 })
    if (destroyed) return
    hello.value = greeting
    if (!['enrollment.status', 'status.get'].every(method => greeting.supported_methods.includes(method))) {
      throw new BridgeError('unsupported_methods', '服务版本不支持此界面所需的状态查询')
    }
    const [device, runtime, summary] = await Promise.all([
      bridge.request('enrollment.status', {}), bridge.request('status.get', {}),
      greeting.supported_methods.includes('config.summary')
        ? bridge.request('config.summary', {}).then(result => ({ result, error: '' }))
          .catch(error => ({ result: null, error: errorMessage(error) }))
        : Promise.resolve({ result: null, error: '' }),
    ])
    if (destroyed) return
    if (device.enrolled !== runtime.enrolled) {
      throw new BridgeError('inconsistent_state', '设备授权状态发生变化，请刷新后重试')
    }
    enrollment.value = device
    status.value = runtime
    if (device.error || runtime.error) {
      enrollmentUri.value = ''
      confirmForget.value = false
    }
    if (greeting.supported_methods.includes('extensions.list')) {
      try { extensions.value = (await bridge.request('extensions.list')).extensions } catch { extensions.value = [] }
    }
    config.value = summary.result
    configIssue.value = summary.error
    connection.value = 'online'
    if (greeting.supported_methods.includes('config.inspect') && !device.error && !runtime.error) {
      try { const result = await bridge.request('config.inspect', {}); if (!destroyed) { inspection.value = result; catalogIssue.value = result.routing_warning ? '部分本地覆盖已失效，相关规则暂显示服务器配置。请重新选择节点或恢复服务器设置。' : '' } }
      catch (error) { inspection.value = null; catalogIssue.value = errorMessage(error) }
    } else { inspection.value = null; catalogIssue.value = '' }
  } catch (error) {
    if (destroyed) return
    issue.value = error instanceof BridgeError ? error : new BridgeError('unexpected_error', '无法读取服务状态')
    connection.value = bridge.available ? 'offline' : 'host_missing'
    status.value = null; enrollment.value = null; config.value = null; inspection.value = null; runtime.value = null
  } finally {
    if (!destroyed) {
      busy.value = false
      checkedAt.value = new Date()
      void readTelemetry()
    }
  }
}

async function enroll(): Promise<void> {
  if (!canAct('enrollment.apply') || !enrollmentPreview.value.preview || enrollment.value?.enrolled) return
  const uri = enrollmentUri.value.trim()
  // Clear the DOM and reactive model before the one-time credential is sent.
  enrollmentUri.value = ''
  operation.value = 'enroll'
  actionNotice.value = ''
  actionFailed.value = false
  try {
    enrollment.value = await bridge.request('enrollment.apply', { uri }, { timeoutMs: 45_000 })
    operation.value = 'sync'
    actionNotice.value = '设备注册成功，正在同步最新配置…'
    try {
      config.value = await bridge.request('config.refresh', {}, { timeoutMs: 45_000 })
      actionNotice.value = '设备已注册，最新配置已同步。点击启动连接即可使用。'
    } catch (error) {
      actionFailed.value = true
      actionNotice.value = `设备已注册，但配置同步失败：${errorMessage(error)}。可以重试同步，无需再次注册。`
    }
  } catch (error) {
    actionFailed.value = true
    actionNotice.value = `${errorMessage(error)}。注册链接已清空；若结果不明确，请先检查设备状态，勿重复兑换同一个注册码。`
  } finally {
    enrollmentUri.value = ''
    operation.value = null
    if (!destroyed) await refresh()
  }
}

async function forget(): Promise<void> {
  if (!confirmForget.value || !canAct('enrollment.forget') || !controls.value.canForget) return
  operation.value = 'forget'
  actionNotice.value = ''
  actionFailed.value = false
  enrollmentUri.value = ''
  try {
    enrollment.value = await bridge.request('enrollment.forget', {}, { timeoutMs: 45_000 })
    config.value = null
    confirmForget.value = false
    actionNotice.value = '已清除此设备的本地注册信息和配置。再次使用需要新的注册链接。'
  } catch (error) {
    actionFailed.value = true
    actionNotice.value = errorMessage(error)
  } finally {
    operation.value = null
    if (!destroyed) await refresh()
  }
}

async function downloadConfig(): Promise<void> {
  if (!canAct('config.refresh') || !enrollment.value?.enrolled) return
  operation.value = 'sync'
  actionNotice.value = ''
  actionFailed.value = false
  try {
    config.value = await bridge.request('config.refresh', {}, { timeoutMs: 45_000 })
    actionNotice.value = configStage(config.value, status.value).detail
  } catch (error) {
    actionFailed.value = true
    actionNotice.value = errorMessage(error)
  } finally {
    operation.value = null
    if (!destroyed) await refresh()
  }
}

async function setServiceRouting(group: string, mode: 'node' | 'default' | 'server', node?: string): Promise<void> {
  if (!canAct('routing.set')) return
  if (mode === 'node' && !node) return
  pendingRouting.value = group
  operation.value = 'routing'
  actionNotice.value = ''
  actionFailed.value = false
  try {
    const params = mode === 'node' ? { group, mode, node: node! } : { group, mode }
    config.value = await bridge.request('routing.set', params, { timeoutMs: 45_000 })
    actionNotice.value = config.value.routing_live ? '出口已切换，新连接立即生效。已有连接继续使用原出口。' : '出口已保存，下次连接生效。'

  } catch (error) {
    actionFailed.value = true
    actionNotice.value = '切换未确认，请以刷新后的出口为准。' + errorMessage(error)
  } finally {
    pendingRouting.value = ''
    operation.value = null
    if (!destroyed) await refresh()
  }
}

async function changeSubscription(action: 'add' | 'refresh' | 'remove', id: string, name = '', url = ''): Promise<void> {
  if (!canAct('subscriptions.save')) return
  operation.value = 'subscription'; actionNotice.value = ''; actionFailed.value = false
  try {
    if (action === 'remove') config.value = await bridge.request('subscriptions.remove', { id }, { timeoutMs: 45_000 })
    else {
      const downloaded = await bridge.request('subscriptions.fetch', action === 'add' ? { url } : { id }, { timeoutMs: 45_000 })
      const nodes = parseSubscription(downloaded.body)
      downloaded.body = ''
      config.value = await bridge.request('subscriptions.save', { name, nodes, ...(action === 'add' ? { url } : { id }) }, { timeoutMs: 45_000 })
    }
    actionNotice.value = action === 'remove' ? '本机订阅已删除。' : config.value.routing_live ? '订阅已保存，节点已加入当前配置，可在首页选择。' : '订阅已保存，下次连接生效。'
    sourceFilter.value = ''
  } catch (error) { actionFailed.value = true; actionNotice.value = errorMessage(error) }
  finally { url = ''; operation.value = null; if (!destroyed) await refresh() }
}

async function validateConfig(): Promise<void> {
  if (!canAct('config.validate') || !stage.value.canValidate) return
  operation.value = 'validate'
  actionNotice.value = ''
  actionFailed.value = false
  try {
    config.value = await bridge.request('config.validate', {}, { timeoutMs: 45_000 })
    actionFailed.value = configStage(config.value, status.value).state !== 'valid'
    actionNotice.value = configStage(config.value, status.value).detail
  } catch (error) {
    actionFailed.value = true
    actionNotice.value = `${errorMessage(error)}。校验不会切换当前连接，请查看最新运行状态。`
  } finally {
    operation.value = null
    if (!destroyed) await refresh()
  }
}

function stopRuntimePolling(): void {
  ++runtimeGeneration
  clearTimeout(runtimeTimer)
}

function startRuntimePolling(): void {
  stopRuntimePolling()
  const generation = runtimeGeneration
  const poll = async (): Promise<void> => {
    try {
      const runtime = await bridge.request('status.get', {})
      if (destroyed || generation !== runtimeGeneration) return
      status.value = runtime
    } catch {
      // The operation and final refresh own error reporting. Never infer a
      // successful connection or retry a mutation from a missed status poll.
    }
    if (!destroyed && generation === runtimeGeneration) runtimeTimer = setTimeout(() => void poll(), 700)
  }
  runtimeTimer = setTimeout(() => void poll(), 400)
}

async function changeConnection(action: 'start' | 'stop'): Promise<void> {
  const method = action === 'start' ? 'connection.start' : 'connection.stop'
  if (!canAct(method) || !(action === 'start' ? controls.value.canStart : controls.value.canStop)) return
  operation.value = action
  actionNotice.value = ''
  actionFailed.value = false
  startRuntimePolling()
  try {
    const result = await bridge.request(method, {}, { timeoutMs: action === 'start' ? 95_000 : 45_000 })
    stopRuntimePolling()
    status.value = result
    const completed = action === 'start'
      ? result.phase === 'RUNNING' && result.core_running && Boolean(result.config?.active_etag)
      : result.phase === 'STOPPED' && !result.core_running && result.config?.active_etag === null
    actionFailed.value = !completed
    actionNotice.value = completed
      ? action === 'start' ? runtimeDetail(result) : '内核已停止，已激活配置已清空。'
      : '操作已返回，但尚未确认预期运行状态。请查看最新状态后决定下一步。'
  } catch (error) {
    actionFailed.value = true
    actionNotice.value = `${errorMessage(error)}。请求不会自动重试，请查看最新运行状态。`
  } finally {
    stopRuntimePolling()
    operation.value = null
    if (!destroyed) await refresh()
  }
}

function refreshWhenVisible(): void {
  if (autoRefresh.value && bridge.available && document.visibilityState === 'visible' && !enrollmentUri.value && !confirmForget.value) void refresh()
}

onMounted(() => {
  try {
    const saved = JSON.parse(localStorage.getItem('sb-easy-display') ?? '{}')
    if (['system', 'light', 'dark'].includes(saved.theme)) theme.value = saved.theme
    if (typeof saved.autoRefresh === 'boolean') autoRefresh.value = saved.autoRefresh
  } catch { /* Use safe display defaults. */ }
  document.documentElement.dataset.theme = theme.value
  void refresh()
  void pollTelemetry()
  // The initial service contract has no subscriptions yet. Bound polling and
  // pause it while hidden; a restored window immediately checks for stale state.
  refreshTimer = setInterval(refreshWhenVisible, 15_000)
  document.addEventListener('visibilitychange', refreshWhenVisible)
})
onBeforeUnmount(() => {
  destroyed = true
  enrollmentUri.value = ''
  clearInterval(refreshTimer)
  clearTimeout(telemetryTimer)
  stopRuntimePolling()
  document.removeEventListener('visibilitychange', refreshWhenVisible)
  bridge.dispose()
})
</script>

<template>
  <div class="app-shell" data-testid="desktop-app" :data-page="page" :data-service-state="connection === 'online' ? 'connected' : connection === 'checking' ? 'loading' : 'disconnected'" :data-enrolled="enrollment?.enrolled === true ? 'true' : 'false'" :data-candidate="config?.candidate_available === true ? 'true' : 'false'" :data-busy="locked ? 'true' : 'false'" :data-validation="stage.state" :data-phase="status?.phase ?? 'UNKNOWN'" :data-core-running="status?.core_running ? 'true' : 'false'" :data-active-etag="configMetadata?.active_etag ?? ''" :data-telemetry="runtime?.running ? 'ready' : 'waiting'">
    <aside class="sidebar">
      <div class="brand"><img :src="brandMark" alt="" /><div><strong>sb-easy<span class="brand-dot">.</span></strong><span>你的网络，由你选择</span></div></div>
      <div class="sidebar-label">工作空间</div>
      <nav aria-label="主导航">
        <button v-for="item in navigation.filter(item => ['overview', 'proxies', 'connections', 'logs'].includes(item.id))" :key="item.id" :data-testid="`nav-${item.id}`" :class="{ selected: page === item.id }" :aria-current="page === item.id ? 'page' : undefined" @click="selectPage(item.id)"><AppIcon :name="item.id" /><span>{{ item.label }}</span></button>
        <div class="advanced-navigation">
          <button class="tools-toggle" data-testid="tools-toggle" :aria-expanded="toolsOpen" aria-controls="advanced-tools" @click="toolsOpen = !toolsOpen"><span>更多工具</span><svg class="tools-chevron" :class="{ expanded: toolsOpen }" viewBox="0 0 24 24" aria-hidden="true"><path d="m9 5 7 7-7 7" /></svg></button>
          <div id="advanced-tools" v-show="toolsOpen">
          <button v-for="item in navigation.filter(item => ['profiles','rules','activity'].includes(item.id))" :key="item.id" :data-testid="`nav-${item.id}`" :class="{ selected: page === item.id }" :aria-current="page === item.id ? 'page' : undefined" @click="selectPage(item.id)"><AppIcon :name="item.id" /><span>{{ item.label }}</span></button>
          </div>
        </div>
        <button v-for="item in enabledExtensions" :key="item.id" :data-testid="`nav-${item.id}`" :class="{selected:page===item.id}" :aria-current="page===item.id ? 'page' : undefined" @click="openExtension(item.id)"><AppIcon :name="item.id"/><span>{{ item.name }}</span></button>
      </nav>
      <div class="sidebar-bottom">
        <button data-testid="nav-diagnostics" class="sidebar-service" @click="selectPage('diagnostics')"><span class="state-dot" :class="{ ready: connection === 'online' }"></span><div><strong>服务 {{ serviceLabel }}</strong><span>{{ hello ? `v${hello.service_version}` : '等待服务响应' }}</span></div><AppIcon name="arrow" /></button>
        <button class="settings-nav" data-testid="nav-settings" :class="{ selected: page === 'settings' }" @click="selectPage('settings')"><AppIcon name="settings" /><span>设置</span></button>
      </div>
    </aside>
    <main id="main-content">
      <header class="page-header"><div><h1>{{ currentPage.label }}</h1><p class="page-description">{{ currentPage.description }}</p></div><div class="header-actions"><span class="status-tag" :class="{ pending: !status?.core_running }"><span class="state-dot" :class="{ ready: status?.core_running }"></span>{{ status?.core_running ? '代理已启动' : '未连接' }}</span><button class="refresh-button" data-testid="status-refresh" :disabled="locked" @click="refresh"><AppIcon name="refresh" :class="{ spinning: busy }" />{{ busy ? '检查中' : '刷新' }}</button></div></header>
      <div v-if="issue && connection !== 'host_missing'" class="error-notice" role="alert"><strong>服务通信未完成</strong><span>{{ issue.message }}</span>
        <template v-if="bridge.available && connection === 'offline'">
          <button class="connect-button" data-testid="service-authorize" :disabled="locked" @click="startService">{{ operation === 'service' ? '等待管理员授权与服务启动…' : '授权并启动服务' }}</button>
          <small>仅启动已安装的后台；不会自动连接代理，无需重启电脑。尚未安装服务时请使用 MSI 安装包。</small>
        </template></div>
      <div v-if="deviceStateError" class="error-notice" role="alert"><strong>设备存储需要修复</strong><span>{{ deviceStateError.message }}</span><code>{{ deviceStateError.code }}</code></div>
      <div v-if="status?.runtime_error" class="error-notice" role="alert"><strong>{{ status.runtime_error.code === 'ROLLED_BACK' ? '已恢复先前配置' : '连接操作需要检查' }}</strong><span>{{ status.runtime_error.message }}</span><code>{{ status.runtime_error.code }}</code></div>
      <div v-if="actionNotice && !(actionFailed && status?.runtime_error && actionNotice.includes(status.runtime_error.message))" class="action-notice" :class="{ failed: actionFailed }" :role="actionFailed ? 'alert' : 'status'">{{ actionNotice }}</div>

      <template v-if="page === 'overview'">
        <section class="connection-card" :class="{ 'is-running': status?.core_running }" aria-labelledby="connection-title" aria-live="polite" :aria-busy="locked" data-testid="connection-summary">
          <div class="connection-top"><div><div class="state-kicker"><span class="state-dot" :class="{ ready: status?.core_running }"></span>{{ status?.core_running ? '本机代理已就绪' : '连接状态' }}</div><h2 id="connection-title">{{ stateLabel }}</h2><p>{{ stateDetail }}</p></div><div class="connection-action"><button v-if="!status?.core_running || controls.canStart || operation === 'start'" class="connect-button" data-testid="connection-start" :disabled="!canAct('connection.start') || !controls.canStart" @click="changeConnection('start')"><AppIcon name="power" />{{ operation === 'start' ? '正在启动…' : controls.startLabel }}</button><button v-if="controls.canStop || operation === 'stop'" class="secondary-button" data-testid="connection-stop" :disabled="!canAct('connection.stop') || !controls.canStop" @click="changeConnection('stop')">{{ operation === 'stop' ? '正在断开…' : '断开连接' }}</button></div></div>
        </section>
        <ServiceRouting v-if="routingGroups.length" :groups="routingGroups" :nodes="routingNodes" :disabled="!canAct('routing.set')" :pending="pendingRouting" :live="config?.routing_live === true" @select="setServiceRouting" />
        <div v-if="catalogIssue" class="error-notice" role="alert">{{ catalogIssue }}</div>
        <section v-if="enrollment?.enrolled && !routingGroups.length" class="panel empty-inline"><p>{{ configIssue || '尚未读取到可用出口，请同步配置或检查服务版本。' }}</p><button class="text-button" @click="selectPage('profiles')">前往配置管理 →</button></section>
        <section class="traffic-metrics" aria-label="实时流量">
          <article><span><AppIcon name="up" />上传速率</span><strong>{{ trafficReady ? bytes(speed?.up) : '—' }}<small v-if="trafficReady && speed">/s</small></strong><p>{{ trafficReady ? `累计 ${bytes(runtime?.upload_total)}` : status?.core_running ? '等待流量数据' : '连接后开始统计' }}</p></article>
          <article><span><AppIcon name="down" />下载速率</span><strong>{{ trafficReady ? bytes(speed?.down) : '—' }}<small v-if="trafficReady && speed">/s</small></strong><p>{{ trafficReady ? `累计 ${bytes(runtime?.download_total)}` : status?.core_running ? '等待流量数据' : '连接后开始统计' }}</p></article>
          <article><span><AppIcon name="connections" />活动连接</span><strong>{{ trafficReady ? runtime?.connection_count : '—' }}</strong><button class="text-button" @click="selectPage('connections')">查看连接 <span>↗</span></button></article>
          <article><span><AppIcon name="proxies" />配置节点</span><strong>{{ runningCatalog?.node_count ?? '—' }}</strong><button class="text-button" @click="selectPage('proxies')">查看代理 <span>↗</span></button></article>
        </section>
        <div v-if="enrollment?.enrolled" class="home-config-link"><span>共享配置 · {{ profileName }}</span><button class="text-button" @click="selectPage('profiles')">管理配置 →</button><button class="text-button" @click="selectPage('rules')">查看规则 →</button></div>
                <section v-if="!enrollment?.enrolled" class="device-card" aria-labelledby="enrollment-title">
          <div class="section-heading"><h2 id="enrollment-title">注册这台设备</h2><span>一次性设备授权</span></div>
          <p class="section-description">在管理面板的“设备”页面生成注册链接，然后粘贴到这里。</p>
          <form @submit.prevent="enroll">
            <label class="input-label" for="enrollment-uri">完整注册链接</label>
            <textarea id="enrollment-uri" v-model="enrollmentUri" data-testid="enrollment-uri" rows="3" maxlength="16384" autocomplete="off" autocapitalize="off" :spellcheck="false" :disabled="locked || !!deviceStateError || enrollment?.enrolled === true" placeholder="sbeasy://enroll?server=…&amp;code=…" aria-describedby="enrollment-privacy"></textarea>
            <p id="enrollment-privacy" class="input-hint">链接仅用于这次注册，提交后立即清空，不保存在界面设置中。</p>
            <div v-if="enrollmentPreview.preview" class="server-preview"><span>将注册到</span><strong>{{ enrollmentPreview.preview.serverOrigin }}</strong></div>
            <p v-if="enrollmentPreview.preview && !enrollmentPreview.preview.secure" class="http-notice" role="status">此服务器使用 HTTP，注册码和设备凭据会通过未加密连接传输。请确认这是可信网络中的服务器。</p>
            <p v-if="enrollmentPreview.error" class="validation-error" role="status">{{ enrollmentPreview.error }}</p>
            <div class="form-footer"><button class="primary-button" data-testid="enrollment-submit" :disabled="!canAct('enrollment.apply') || !enrollmentPreview.preview">{{ operation === 'enroll' ? '正在注册…' : '注册设备' }}</button><span v-if="deviceStateError">请先修复设备存储，原有资料不会被覆盖</span><span v-else-if="connection !== 'online'">请先连接本机服务</span><span v-else-if="!supports('enrollment.apply')">当前服务版本不支持设备注册</span></div>
          </form>
        </section>

      </template>

      <template v-else-if="page === 'proxies'">
        <div class="content-toolbar"><div class="segments" aria-label="配置来源"><button :class="{ active: catalogSource === 'active' }" @click="catalogSource = 'active'">当前运行</button><button :class="{ active: catalogSource === 'candidate' }" @click="catalogSource = 'candidate'">已下载配置</button></div><label class="search-box"><AppIcon name="search" /><input v-model="search" :placeholder="page === 'proxies' ? '搜索节点或协议' : '搜索域名、规则或出口'" :aria-label="page === 'proxies' ? '搜索节点' : '搜索路由规则'" /></label></div>
        <div class="data-source-line"><span>{{ sourceLabel }} · <code>{{ shortVersion(catalog?.etag) }}</code></span><span v-if="catalog">{{ page === 'proxies' ? `${catalog.node_count} 个出站` : `${catalog.rule_count} 条规则` }}</span></div>
        <div v-if="catalogIssue" class="error-notice" role="alert">{{ catalogIssue }}</div>
        <div v-if="!catalog" class="panel empty-state"><AppIcon :name="page" /><h2>{{ catalogSource === 'active' ? '尚无运行配置' : '还没有下载配置' }}</h2><p>{{ catalogSource === 'active' ? '启动连接后可查看实际生效的节点与规则，也可以先查看已下载配置。' : '完成设备注册并同步配置后，节点与路由规则会显示在这里。' }}</p><button class="secondary-button" @click="catalogSource === 'active' && inspection?.candidate ? catalogSource = 'candidate' : selectPage('profiles')">{{ catalogSource === 'active' && inspection?.candidate ? '查看已下载配置' : '前往配置管理' }}</button></div>
        <template v-else>
          <SubscriptionsPanel :summary="subscriptionSummary" :disabled="!canAct('subscriptions.save')" :busy="operation === 'subscription'" :filter="sourceFilter" @filter="sourceFilter = $event" @add="(name, url) => changeSubscription('add', '', name, url)" @refresh="(id, name) => changeSubscription('refresh', id, name)" @remove="id => changeSubscription('remove', id)" />
          <section v-if="groups.length" class="proxy-groups"><article v-for="group in groups" :key="group.tag" class="panel group-card"><div class="section-heading"><span class="group-icon"><AppIcon name="proxies" /></span><span class="status-tag">{{ nodeKind(group.type) }}</span></div><h2>{{ group.tag }}</h2><p>当前出口</p><strong>{{ group.selected || '由内核自动选择' }}</strong><span class="group-count">{{ group.member_count }} 个成员 · {{ catalogSource === 'active' && runtime ? '内核实时状态' : '配置初始值' }}</span></article></section>
          <div class="section-heading node-heading"><h2>节点列表 <span>{{ filteredNodes.length }}</span></h2><div class="segments"><button :class="{ active: nodeFilter === 'all' }" @click="nodeFilter = 'all'">全部</button><button :class="{ active: nodeFilter === 'nodes' }" @click="nodeFilter = 'nodes'">节点</button><button :class="{ active: nodeFilter === 'groups' }" @click="nodeFilter = 'groups'">代理组</button></div></div>
          <div class="node-grid"><article v-for="(node, index) in filteredNodes" :key="`${node.tag}-${index}`" class="node-card" :class="{ 'default-node': node.tag === catalog.final }"><div class="node-avatar">{{ node.member_count ? '组' : node.type.toLowerCase() === 'direct' ? '直' : Array.from(nodeLabel(node.tag))[0]?.toUpperCase() || 'N' }}</div><div class="node-copy"><h3>{{ nodeLabel(node.tag) || '未命名出站' }}</h3><span>{{ nodeKind(node.type) }} · {{ sourceMap.get(node.tag)?.name ?? '其他 / 未知来源' }}<b v-if="node.tag === catalog.final">默认出口</b></span></div><span class="node-delay" :class="{ measured: node.delay }">{{ node.delay ? `${node.delay} ms` : '未测速' }}</span><details v-if="node.members.length"><summary>查看组成员</summary><ul><li v-for="member in node.members" :key="member">{{ member }}</li></ul><p v-if="node.member_count > node.members.length">另有 {{ node.member_count - node.members.length }} 个成员</p></details></article></div>
          <div v-if="!filteredNodes.length" class="panel empty-inline"><p>没有匹配的节点</p><button class="text-button" @click="search = ''; nodeFilter = 'all'; sourceFilter = ''">清除筛选</button></div><p class="collection-note">服务出口可在“连接”页面选择。此处延迟仅显示内核已有的测速记录，尚未提供主动测速。</p><p v-if="catalog.node_count > catalog.nodes.length" class="collection-note">配置包含 {{ catalog.node_count }} 个出站，当前最多展示 1024 个。</p>
        </template>

      </template>

      <template v-else-if="page === 'profiles'">
        <section class="config-workflow"><div :class="{ done: enrollment?.enrolled }"><span>01</span><strong>设备授权</strong><p>{{ deviceLabel }}</p></div><div :class="{ done: config?.candidate_available }"><span>02</span><strong>配置同步</strong><p>{{ config?.candidate_available ? '已有下载版本' : '等待下载' }}</p></div><div :class="{ done: stage.state === 'valid' }"><span>03</span><strong>内核校验</strong><p>{{ stage.label }}</p></div><div :class="{ done: status?.core_running }"><span>04</span><strong>启动连接</strong><p>{{ coreLabel }}</p></div></section>
                <section v-if="!enrollment?.enrolled" class="device-card" aria-labelledby="enrollment-title">
          <div class="section-heading"><h2 id="enrollment-title">注册这台设备</h2><span>一次性设备授权</span></div>
          <p class="section-description">在管理面板的“设备”页面生成注册链接，然后粘贴到这里。</p>
          <form @submit.prevent="enroll">
            <label class="input-label" for="enrollment-uri">完整注册链接</label>
            <textarea id="enrollment-uri" v-model="enrollmentUri" data-testid="enrollment-uri" rows="3" maxlength="16384" autocomplete="off" autocapitalize="off" :spellcheck="false" :disabled="locked || !!deviceStateError || enrollment?.enrolled === true" placeholder="sbeasy://enroll?server=…&amp;code=…" aria-describedby="enrollment-privacy"></textarea>
            <p id="enrollment-privacy" class="input-hint">链接仅用于这次注册，提交后立即清空，不保存在界面设置中。</p>
            <div v-if="enrollmentPreview.preview" class="server-preview"><span>将注册到</span><strong>{{ enrollmentPreview.preview.serverOrigin }}</strong></div>
            <p v-if="enrollmentPreview.preview && !enrollmentPreview.preview.secure" class="http-notice" role="status">此服务器使用 HTTP，注册码和设备凭据会通过未加密连接传输。请确认这是可信网络中的服务器。</p>
            <p v-if="enrollmentPreview.error" class="validation-error" role="status">{{ enrollmentPreview.error }}</p>
            <div class="form-footer"><button class="primary-button" data-testid="enrollment-submit" :disabled="!canAct('enrollment.apply') || !enrollmentPreview.preview">{{ operation === 'enroll' ? '正在注册…' : '注册设备' }}</button><span v-if="deviceStateError">请先修复设备存储，原有资料不会被覆盖</span><span v-else-if="connection !== 'online'">请先连接本机服务</span><span v-else-if="!supports('enrollment.apply')">当前服务版本不支持设备注册</span></div>
          </form>
        </section>

                <section v-if="enrollment?.enrolled" class="device-card" aria-labelledby="device-title">
          <div class="section-heading"><h2 id="device-title">{{ deviceMetadata?.host_name || '已注册设备' }}</h2><span class="status-tag">已授权</span></div>
          <dl class="diagnostic-list compact"><div><dt>管理服务器</dt><dd>{{ deviceMetadata?.server_origin || '尚未读取' }}</dd></div><div><dt>配置 Profile</dt><dd>{{ profileName }}</dd></div></dl>
          <div v-if="!confirmForget" class="form-footer"><button class="text-button danger-text" :disabled="!canAct('enrollment.forget') || !controls.canForget" @click="confirmForget = true">忘记此设备</button><span v-if="!controls.canForget">请先断开连接</span></div>
          <div v-else class="forget-confirm" role="group" aria-labelledby="forget-title"><h3 id="forget-title">清除此电脑上的注册信息？</h3><p>本地设备凭据和已下载配置将被清除。再次注册需要在管理面板生成新的注册链接。</p><div class="confirmation-actions"><button class="secondary-button" :disabled="locked" @click="confirmForget = false">保留设备</button><button class="danger-button" data-testid="enrollment-forget-confirm" :disabled="!canAct('enrollment.forget') || !controls.canForget" @click="forget">{{ operation === 'forget' ? '正在清除…' : '确认忘记设备' }}</button></div></div>
        </section>

                <section v-if="enrollment?.enrolled" class="device-card" aria-labelledby="config-title" data-testid="candidate-summary">
          <div class="section-heading"><h2 id="config-title">服务器配置</h2><button class="secondary-button" data-testid="config-refresh" :disabled="!canAct('config.refresh')" @click="downloadConfig">{{ operation === 'sync' ? '正在下载…' : '下载最新配置' }}</button></div>
          <div class="config-stage"><span class="status-tag" :class="{ pending: configMetadata?.candidate_available && stage.state !== 'valid' }">{{ stage.label }}</span><p>{{ stage.detail }}</p></div>
          <dl class="diagnostic-list compact"><div><dt>候选配置版本</dt><dd><code>{{ configMetadata?.downloaded_etag || '尚未下载' }}</code></dd></div><div><dt>当前激活版本</dt><dd><code>{{ configMetadata?.active_etag || '无 · 尚未激活' }}</code></dd></div><div v-if="configMetadata?.last_good_etag"><dt>上次可用版本</dt><dd><code>{{ configMetadata.last_good_etag }}</code></dd></div><div><dt>规则来源</dt><dd>{{ configMetadata?.rule_source || '尚未读取' }}</dd></div><div><dt>Profile</dt><dd>{{ profileName }}</dd></div></dl>
          <div v-if="config?.candidate_available" class="config-counts" aria-label="候选配置摘要"><span><strong>{{ config.counts.inbounds }}</strong> 入站</span><span><strong>{{ config.counts.outbounds }}</strong> 出站</span><span><strong>{{ config.counts.rules }}</strong> 路由规则</span></div>
          <div class="form-footer"><button class="secondary-button" data-testid="config-validate" :disabled="!canAct('config.validate') || !stage.canValidate" @click="validateConfig">{{ operation === 'validate' ? '正在校验…' : stage.state === 'valid' ? '重新校验配置' : '校验配置' }}</button><span v-if="config?.validation">sing-box {{ config.validation.core_version }}</span></div>
          <p v-if="stage.state === 'invalid' && config?.validation?.error" class="validation-error" role="alert">{{ config.validation.error.message }} <code>{{ config.validation.error.code }}</code></p>
          <p v-if="configIssue" class="validation-error" role="status">配置摘要暂不可用：{{ configIssue }}</p>
          <p v-if="!supports('config.refresh')" class="input-hint">当前服务版本不支持配置下载。</p>
          <p v-if="!supports('config.validate')" class="input-hint">当前服务版本不支持内核校验。</p>
        </section>

        <section class="panel help-card"><h2>配置生效流程</h2><p>同步只下载新的候选版本，校验通过后在总览点击“启动连接”或“应用新配置”。正在运行的版本会保留到切换成功；新版本启动失败时服务会尝试恢复上次可用版本。</p><button class="text-button" @click="selectPage('overview')">前往连接控制 →</button></section>
      </template>

      <NetworkToolsView v-else-if="page === 'connections' || page === 'rules'" :key="page" :bridge="bridge" :initial-tab="page" standalone />
      <LogsView v-else-if="page === 'logs'" :bridge="bridge" />
      <ExtensionsPanel v-else-if="page === 'extensions'" :bridge="bridge" @changed="extensions = $event" @open="openExtension" />
      <ExtensionView v-else-if="extensionPage" :key="extensionPage.id" :id="extensionPage.id" :bridge="bridge" :server="deviceMetadata?.server_origin ?? ''" @back="selectPage('extensions')" />
      <template v-else-if="page === 'activity'">
        <div class="content-toolbar"><span class="data-source-line">本次界面会话 · {{ activities.length }} 条记录</span><button class="secondary-button" :disabled="!activities.length" @click="activities = []">清空记录</button></div><section class="panel activity-panel"><div v-for="item in activities" :key="item.id" class="activity-row" :class="{ failed: item.failed }"><time>{{ item.time }}</time><span class="activity-marker"><AppIcon :name="item.failed ? 'activity' : 'check'" /></span><div><h3>{{ item.title }}</h3><p>{{ item.detail }}</p></div></div><div v-if="!activities.length" class="empty-state"><AppIcon name="activity" /><h2>还没有活动记录</h2><p>配置同步、连接启停与状态变化会记录在这里。</p></div></section><p class="collection-note">记录只保留在当前界面内存中，最多 100 条；关闭窗口后清空。内核运行记录请查看“运行日志”。</p>
      </template>

      <template v-else-if="page === 'settings'">
        <section class="panel settings-panel"><div class="section-heading"><h2>扩展商店</h2><button class="secondary-button" @click="selectPage('extensions')">浏览扩展 →</button></div><p class="input-hint">流量采集等高级能力按需安装，基础代理不依赖扩展。</p><button v-if="captureEnabled" class="text-button" @click="selectPage('capture')">打开流量采集 →</button></section>
        <section class="panel settings-panel" aria-labelledby="ipv6-title">
          <div class="section-heading"><h2 id="ipv6-title">IPv6 支持</h2><span class="status-tag">最近检查 {{ checkedTime }}</span></div>
          <div class="setting-row"><div><h3>本机 IPv6 网络</h3><p>检查可用网卡上的公网地址与默认路由，不代表已通过互联网连通测试。</p></div><strong>{{ ipv6Network }}</strong></div>
          <div class="setting-row"><div><h3>IPv6 代理接管</h3><p>检查运行中的 TUN 网卡路由；具体流量仍按分流规则决定直连或代理。</p></div><strong>{{ ipv6Tunnel }}</strong></div>
          <div class="setting-row"><div><h3>节点 IPv6 出口</h3><p>本机没有公网 IPv6 也可以由代理节点连接 IPv6 网站，但需节点本身支持。</p></div><strong>尚未实测</strong></div>
          <p class="input-hint">启用双栈需要配置 IPv6 TUN 地址和路由，并验证节点出口。当前检测不会修改网络设置，也不等同于完整的防泄露测试。</p>
          <button class="text-button" @click="selectPage('diagnostics')">查看连接诊断 →</button>
        </section>
        <section class="panel settings-panel"><div class="section-heading"><h2>外观与显示</h2><AppIcon name="settings" /></div><div class="setting-row"><div><h3>主题</h3><p>选择喜欢的外观，或跟随 Windows。</p></div><div class="segments" aria-label="主题选择"><button v-for="item in [{ id: 'system', label: '跟随系统' }, { id: 'light', label: '浅色' }, { id: 'dark', label: '深色' }] as const" :key="item.id" :data-testid="`theme-${item.id}`" :class="{ active: theme === item.id }" @click="theme = item.id">{{ item.label }}</button></div></div><div class="setting-row"><div><h3>自动刷新</h3><p>流量每 2 秒、服务状态每 15 秒更新；窗口隐藏时暂停。</p></div><button class="toggle" role="switch" :aria-checked="autoRefresh" :class="{ enabled: autoRefresh }" aria-label="自动刷新" @click="autoRefresh = !autoRefresh"><span></span></button></div><p class="input-hint">显示偏好保存在此电脑；活动记录和设备凭据不会存入界面设置。</p></section>
        <section class="panel settings-panel"><div class="section-heading"><h2>网络接入</h2><span class="status-tag" :class="{ pending: !status?.tun_active }">{{ status?.tun_active ? 'TUN 已启用' : '按下发配置启动' }}</span></div><div class="setting-row"><div><h3>TUN 虚拟网卡</h3><p>由服务器配置决定是否启用，需要具有管理员权限的服务。</p></div><strong>{{ status?.tun_active ? '运行中' : '未启用' }}</strong></div><div class="setting-row"><div><h3>本地代理</h3><p>将支持代理的应用设置为此端口，流量才会经过内核。</p></div><code>{{ proxyEndpoint ? `${proxyEndpoint.listen}:${proxyEndpoint.port}` : '未配置' }}</code></div><div class="setting-row"><div><h3>Windows 系统代理</h3><p>当前使用 TUN 或应用内代理设置；系统代理开关尚未接入。</p></div><span class="muted">未接管</span></div></section>
        <section class="panel settings-panel"><div class="section-heading"><h2>关于 sb-easy</h2><span class="preview-badge">Windows 开发预览</span></div><div class="environment-row"><span>本机服务</span><code>{{ hello?.service_version ?? '尚未读取' }}</code></div><div class="environment-row"><span>sing-box</span><code>{{ config?.validation?.core_version ?? '尚未读取' }}</code></div><div class="environment-row"><span>设备名称</span><strong>{{ deviceMetadata?.host_name ?? '尚未注册' }}</strong></div><div class="environment-row"><span>管理服务</span><code>{{ deviceMetadata?.server_origin ?? '尚未注册' }}</code></div><button class="text-button" @click="selectPage('diagnostics')">查看连接诊断 →</button><button class="text-button manage-device" @click="selectPage('profiles')">管理设备授权 →</button></section>
      </template>
      <template v-else>        <section class="diagnostics-card" aria-labelledby="diagnostics-title">
          <div class="section-heading"><h2 id="diagnostics-title">连接状态</h2><span>最近检查 {{ checkedTime }}</span></div>
          <dl class="diagnostic-list">
            <div><dt>原生宿主</dt><dd>{{ bridge.available ? 'WebView2 通信桥已就绪' : '未检测到原生通信桥' }}</dd></div>
            <div><dt>本机服务</dt><dd>{{ serviceLabel }}</dd></div>
            <div><dt>协议版本</dt><dd>{{ hello ? `v${hello.protocol_version}` : '尚未协商' }}</dd></div>
            <div><dt>服务版本</dt><dd>{{ hello?.service_version ?? '尚未读取' }}</dd></div>
            <div><dt>设备授权</dt><dd>{{ deviceLabel }}</dd></div>
            <div><dt>运行阶段</dt><dd><code>{{ status?.phase ?? '尚未读取' }}</code></dd></div>
            <div v-if="deviceStateError"><dt>设备存储错误</dt><dd><code>{{ deviceStateError.code }}</code></dd></div>
            <div><dt>本机启动条件</dt><dd>{{ status ? status.connection_available ? '内核和候选配置可用' : '尚未就绪' : '尚未读取' }}</dd></div>
            <div><dt>TUN 状态</dt><dd>{{ status?.tun_active === true ? '已启用' : status?.tun_active === false ? '未启用' : '服务尚未提供' }}</dd></div>
            <div><dt>本机 IPv6</dt><dd>{{ ipv6Network }}</dd></div>
            <div><dt>IPv6 接管</dt><dd>{{ ipv6Tunnel }}</dd></div>
            <div><dt>节点 IPv6 出口</dt><dd>尚未实测</dd></div>
            <div><dt>互联网连通性</dt><dd>尚未检测</dd></div>
            <div v-if="status?.runtime_error"><dt>运行错误</dt><dd><code>{{ status.runtime_error.code }}</code></dd></div>
          </dl>
          <div v-if="issue" class="diagnostic-error"><span>最近通信结果</span><code>{{ issue.code }}</code><p>{{ issue.message }}</p></div>
          <section class="help-card"><h3>离线诊断记录</h3><p>此测试版自动保存内核调试日志，记录 DNS、分流出口、连接错误及启动/停止过程，重启后仍保留，最多约 16 MB。</p><p>测试失败时先右键托盘图标，选择“导出诊断包（离线）”，或运行安装目录中的 <strong>Export-Diagnostics.cmd</strong>，再恢复其他代理。诊断包保存在桌面，不需要联网；包含访问域名、IP 和节点名称，凭据已过滤，不包含原始配置。</p></section>
          <details v-if="hello" class="protocol-details"><summary>服务支持的操作</summary><ul><li v-for="method in hello.supported_methods" :key="method"><code>{{ method }}</code></li></ul></details>
        </section>
</template>
      <footer class="page-footer"><span><i :class="{ ready: connection === 'online' }"></i>{{ deviceMetadata?.host_name || 'Windows 客户端' }} · 服务 {{ serviceLabel }}</span><span>最近检查 {{ checkedTime }} · {{ autoRefresh ? '自动刷新' : '手动刷新' }}</span></footer>
    </main>
  </div>
</template>
