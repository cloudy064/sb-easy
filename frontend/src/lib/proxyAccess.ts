export const ACCESS_TAG = 'sb-easy-access'
export interface AccessUser { username: string; password: string; outbound: string; kind?: 'group' | 'node' | 'legacy'; nodeId?: string }
export interface AccessNode { id: string; tag: string; enabled: boolean }
export const fixedUsername = (id: string) => `node_${id}`
export const fixedOutbound = (id: string) => `sb-easy-node-${id}`
export interface ProxyAccess { enabled: boolean; listen: string; port: number; users: AccessUser[] }
export function isAccessRule(rule: any): boolean {
  return rule?.inbound === ACCESS_TAG || (Array.isArray(rule?.inbound) && rule.inbound.length === 1 && rule.inbound[0] === ACCESS_TAG)
}
export function readAccess(config: any): ProxyAccess {
  const inbound = config.inbounds?.find((i: any) => i.tag === ACCESS_TAG)
  return { enabled: !!inbound, listen: inbound?.listen ?? '127.0.0.1', port: inbound?.listen_port ?? 1081,
    users: (inbound?.users ?? []).map((u: any) => {
      const outbound = config.route?.rules?.find((r: any) => isAccessRule(r) && (r.auth_user === u.username || (r.auth_user?.length === 1 && r.auth_user[0] === u.username)))?.outbound ?? ''
      return { ...u, outbound, ...(u.username.startsWith('node_') ? { kind: 'node', nodeId: u.username.slice(5) } : {}) }
    }) }
}
export function writeAccess(config: any, access: ProxyAccess, targets: string[], nodes: AccessNode[] = []): any {
  const result = structuredClone(config)
  result.inbounds = (result.inbounds ?? []).filter((i: any) => i.tag !== ACCESS_TAG)
  result.route ??= {}
  result.route.rules = (result.route.rules ?? []).filter((r: any) => !isAccessRule(r))
  if (!access.enabled) return result
  if (!Number.isInteger(access.port) || access.port < 1 || access.port > 65535) throw Error('端口必须在 1–65535 之间')
  if (!access.listen.trim()) throw Error('请填写监听地址')
  if (result.inbounds.some((i: any) => i.listen_port === access.port)) throw Error('该端口已被其他入口使用')
  if (!access.users.length) throw Error('请至少添加一个用户名；如不再使用，请关闭入口')
  const names = new Set<string>()
  for (const user of access.users) {
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(user.username)) throw Error('用户名仅支持 1–64 位字母、数字、下划线和短横线')
    if (names.has(user.username)) throw Error('用户名不能重复')
    names.add(user.username)
    if (!user.password || /[\x00-\x1f\x7f]/.test(user.password)) throw Error('请为每个用户名设置有效密钥')
    if (user.kind === 'node' || user.username.startsWith('node_')) {
      if (!user.nodeId || user.username !== fixedUsername(user.nodeId) || user.outbound !== fixedOutbound(user.nodeId)) throw Error('固定入口的用户名必须与节点 ID 一致')
      const existing = readAccess(config).users.some(u => u.username === user.username && u.outbound === user.outbound)
      if (!existing && !nodes.some(n => n.id === user.nodeId && n.enabled)) throw Error('请选择已启用的节点')
    } else if (!targets.includes(user.outbound)) throw Error(`请为 ${user.username} 选择可用规则组`)
  }
  result.inbounds.push({ type: 'mixed', tag: ACCESS_TAG, listen: access.listen.trim(), listen_port: access.port,
    users: access.users.map(({ username, password }) => ({ username, password })) })
  result.route.rules.unshift(...access.users.map(u => ({ inbound: ACCESS_TAG, auth_user: u.username, action: 'route', outbound: u.outbound })),
    { inbound: ACCESS_TAG, action: 'reject' })
  return result
}
export function proxyUrl(host: string, port: number, user: AccessUser, scheme = 'http'): string {
  const raw = host.trim().replace(/^\[|\]$/g, '')
  if (!raw || /[\s/@?#]/.test(raw)) throw Error('请填写运行 agent 的主机 IP 或域名，不含协议和路径')
  return `${scheme}://${encodeURIComponent(user.username)}:${encodeURIComponent(user.password)}@${raw.includes(':') ? `[${raw}]` : raw}:${port}`
}
export function newAccessKey(): string {
  const bytes = new Uint8Array(24)
  if (!globalThis.crypto?.getRandomValues) throw Error('当前浏览器无法安全生成密钥，请手动填写')
  globalThis.crypto.getRandomValues(bytes)
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}
