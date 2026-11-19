import type { TailscaleEndpoint, TailscaleStatus } from './protocol.js'

export interface TailscaleDisplay {
  label: string
  detail: string
  tone: 'ready' | 'pending' | 'warning' | 'neutral'
}

export function tailscaleEndpointDisplay(endpoint: TailscaleEndpoint): TailscaleDisplay {
  if (endpoint.self?.expired) return { label: '登录已过期', detail: '请在中央面板更新授权，再同步本机配置。', tone: 'warning' }
  switch (endpoint.backend_state) {
    case 'Running': return endpoint.self?.online
      ? { label: '已连接', detail: '本机已连接 Tailscale 网络。', tone: 'ready' }
      : { label: '离线', detail: '已获取设备身份，当前尚未确认在线。', tone: 'warning' }
    case 'NeedsLogin': return { label: '需要登录', detail: '请检查中央面板中此设备的授权密钥，然后重新同步。', tone: 'warning' }
    case 'NeedsMachineAuth': return { label: '等待设备批准', detail: '请在 Tailscale 管理后台批准此设备。', tone: 'warning' }
    case 'Starting': return { label: '正在连接', detail: '正在连接 Tailscale，请稍候。', tone: 'pending' }
    case 'Stopped': return { label: '已停止', detail: 'Tailscale 当前未连接。', tone: 'neutral' }
    case 'NoState': case '': return { label: '等待初始化', detail: '尚未收到 Tailscale 的连接状态。', tone: 'pending' }
    default: return { label: '状态待确认', detail: '暂时无法确认 Tailscale 连接状态，请稍后刷新。', tone: 'neutral' }
  }
}

export function tailscaleDisplay(value: TailscaleStatus | null, context: {
  supported: boolean; connected: boolean; running: boolean; issue: string; pending?: boolean
}): TailscaleDisplay {
  if (!context.connected) return { label: '等待本机服务', detail: '连接本机服务后可读取 Tailscale 状态。', tone: 'neutral' }
  if (!context.supported) return { label: '服务需要更新', detail: '当前本机服务尚未提供 Tailscale 状态，请安装新版服务后重新打开网页。', tone: 'neutral' }
  if (context.issue) return { label: '状态暂不可用', detail: context.issue, tone: 'warning' }
  if (!value) return context.pending
    ? { label: '正在读取', detail: '正在读取此设备的 Tailscale 配置和连接状态。', tone: 'pending' }
    : { label: '尚未读取', detail: '点击“刷新状态”获取此设备的 Tailscale 配置和连接状态。', tone: 'neutral' }
  if (!value.configured && !value.active) return { label: '未配置', detail: '在中央面板为此设备启用 Tailscale，保存后同步本机配置。', tone: 'neutral' }
  if (!context.running) return { label: '未启动', detail: 'Tailscale 配置已保留，启动上方连接后可查看实时状态。', tone: 'neutral' }
  if (!value.active) return { label: '待应用', detail: 'Tailscale 配置已同步，请在上方应用新配置。', tone: 'pending' }
  if (!value.available) return { label: '状态暂不可用', detail: 'Tailscale 配置已加载，暂时无法读取连接状态，请稍后刷新。', tone: 'warning' }
  if (!value.endpoints.length) return { label: '等待初始化', detail: 'Tailscale 配置已加载，正在等待设备状态。', tone: 'pending' }
  const states = value.endpoints.map(tailscaleEndpointDisplay)
  if (states.every(state => state.tone === 'ready')) return { label: '已连接', detail: '使用下方 Tailscale 地址访问本机。', tone: 'ready' }
  return states.find(state => state.tone === 'warning') ?? states.find(state => state.tone !== 'ready')!
}
