import { parse } from 'yaml'

export type Outbound = Record<string, unknown> & { tag: string; type: string; server: string; server_port: number }
const protocols = new Set(['shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'http', 'socks'])
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
const text = (v: unknown) => typeof v === 'string' ? v : ''
function decode(v: string): string {
  const normalized = v.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/')
  const bytes = Uint8Array.from(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=')), c => c.charCodeAt(0))
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
}
function transport(n: Record<string, unknown>, network: string, path: unknown, host: unknown) {
  if (!network || network === 'tcp') return
  if (network === 'ws') n.transport = { type: 'ws', path: text(path) || '/', ...(host ? { headers: { Host: text(host) } } : {}) }
  else if (network === 'grpc') n.transport = { type: 'grpc', service_name: text(path) }
  else throw new Error('不支持此传输方式')
}
function uri(line: string): Record<string, unknown> {
  if (line.startsWith('vmess://')) {
    const p = JSON.parse(decode(line.slice(8))) as Record<string, unknown>
    const n: Record<string, unknown> = { type: 'vmess', tag: p.ps, server: p.add, server_port: Number(p.port), uuid: p.id, security: p.scy || 'auto', alter_id: Number(p.aid || 0) }
    transport(n, text(p.net), p.path, p.host)
    if (p.tls === 'tls') n.tls = { enabled: true, server_name: p.sni || p.host || p.add }
    return n
  }
  // SIP002 also permits the entire authority to be base64 encoded.
  if (line.startsWith('ss://') && !line.split('#')[0].includes('@')) {
    const [authority, fragment] = line.slice(5).split('#')
    line = `ss://${decode(authority)}${fragment ? `#${fragment}` : ''}`
  }
  const u = new URL(line)
  const kind = u.protocol.slice(0, -1)
  const type = kind === 'ss' ? 'shadowsocks' : kind === 'hy2' ? 'hysteria2' : kind
  if (!protocols.has(type)) throw new Error('不支持此协议')
  const q = u.searchParams
  const n: Record<string, unknown> = { type, tag: decodeURIComponent(u.hash.slice(1)) || u.hostname, server: u.hostname.replace(/^\[|\]$/g, ''), server_port: Number(u.port || (type === 'http' ? 80 : type === 'socks' ? 1080 : 443)) }
  const user = decodeURIComponent(u.username), password = decodeURIComponent(u.password)
  if (type === 'shadowsocks') {
    const auth = password ? `${user}:${password}` : decode(user)
    const colon = auth.indexOf(':')
    if (colon < 1) throw new Error('缺少认证信息')
    n.method = auth.slice(0, colon); n.password = auth.slice(colon + 1)
    if (q.has('plugin')) throw new Error('暂不支持分享链接中的插件参数')
  } else if (type === 'vless' || type === 'tuic') { n.uuid = user; if (type === 'tuic') n.password = password; if (q.get('flow')) n.flow = q.get('flow') }
  else if (type === 'trojan' || type === 'hysteria2') n.password = password ? `${user}:${password}` : user
  else { n.username = user; n.password = password }
  transport(n, q.get('type') || '', q.get('serviceName') || q.get('path'), q.get('host'))
  if (['trojan', 'hysteria2', 'tuic'].includes(type) || ['tls', 'reality'].includes(q.get('security') || '')) {
    const tls: Record<string, unknown> = { enabled: true, server_name: q.get('sni') || q.get('peer') || n.server }
    if (q.get('allowInsecure') === '1' || q.get('insecure') === '1') tls.insecure = true
    if (q.get('alpn')) tls.alpn = q.get('alpn')!.split(',')
    if (q.get('fp')) tls.utls = { enabled: true, fingerprint: q.get('fp') }
    if (q.get('security') === 'reality') { tls.reality = { enabled: true, public_key: q.get('pbk'), short_id: q.get('sid') || '' }; tls.utls ||= { enabled: true, fingerprint: 'chrome' } }
    n.tls = tls
  }
  if (type === 'hysteria2' && q.get('obfs')) n.obfs = { type: q.get('obfs'), password: q.get('obfs-password') }
  return n
}
function clash(p: Record<string, unknown>): Record<string, unknown> {
  const type = p.type === 'ss' ? 'shadowsocks' : p.type === 'hy2' ? 'hysteria2' : p.type === 'socks5' ? 'socks' : p.type
  const n: Record<string, unknown> = { type, tag: p.name, server: p.server, server_port: Number(p.port) }
  for (const key of ['uuid', 'password', 'username', 'flow']) if (p[key] !== undefined) n[key] = p[key]
  if (type === 'shadowsocks') { n.method = p.cipher; if (p.plugin) throw new Error('暂不支持此订阅的插件参数') }
  if (type === 'vmess') { n.security = p.cipher || 'auto'; n.alter_id = Number(p.alterId || 0) }
  const ws = record(p['ws-opts']) ? p['ws-opts'] : {}
  const grpc = record(p['grpc-opts']) ? p['grpc-opts'] : {}
  transport(n, text(p.network), p.network === 'grpc' ? grpc['grpc-service-name'] : ws.path, record(ws.headers) ? ws.headers.Host : '')
  if (p.tls === true || ['trojan', 'hysteria2', 'tuic'].includes(String(type)) || p['reality-opts']) {
    const tls: Record<string, unknown> = { enabled: true, server_name: p.servername || p.sni || p.server }
    if (p['skip-cert-verify'] === true) tls.insecure = true
    if (Array.isArray(p.alpn)) tls.alpn = p.alpn
    if (p['client-fingerprint']) tls.utls = { enabled: true, fingerprint: p['client-fingerprint'] }
    if (record(p['reality-opts'])) { tls.reality = { enabled: true, public_key: p['reality-opts']['public-key'], short_id: p['reality-opts']['short-id'] || '' }; tls.utls ||= { enabled: true, fingerprint: 'chrome' } }
    n.tls = tls
  }
  if (type === 'hysteria2' && p.obfs) n.obfs = { type: p.obfs, password: p['obfs-password'] }
  if (type === 'tuic' && p['congestion-controller']) n.congestion_control = p['congestion-controller']
  return n
}

/** Parse locally; neither URLs nor credentials are sent to a conversion service. */
export function parseSubscription(body: string): Outbound[] {
  if (!body.trim() || body.length > 256 * 1024) throw new Error('订阅为空或超过 256 KB')
  let rows: unknown[], convert: (row: any) => unknown = row => row
  try {
    const content = body.trim()
    if (content.startsWith('{') || content.startsWith('[')) {
      const json: unknown = JSON.parse(content)
      rows = Array.isArray(json) ? json : record(json) && Array.isArray(json.outbounds) ? json.outbounds : []
      rows = rows.filter(row => !record(row) || !['direct', 'block', 'dns', 'selector', 'urltest'].includes(text(row.type)))
    } else if (/^\s*proxies\s*:/m.test(content)) {
      const yaml: unknown = parse(content, { maxAliasCount: 30, prettyErrors: false, logLevel: 'silent' })
      rows = record(yaml) && Array.isArray(yaml.proxies) ? yaml.proxies : []
      convert = clash
    } else {
      const decoded = content.includes('://') ? content : decode(content)
      rows = decoded.split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'))
      convert = uri
    }
  } catch { throw new Error('无法解析订阅，请使用 Clash YAML、sing-box JSON 或代理分享链接订阅') }
  if (!rows.length || rows.length > 256) throw new Error('订阅须包含 1–256 个节点')
  const names = new Set<string>()
  return rows.map((row, index) => {
    try {
      const n = convert(row)
      if (!record(n) || !protocols.has(text(n.type)) || !text(n.server) || !text(n.tag) || new TextEncoder().encode(text(n.tag)).length > 80 || /[\x00-\x1f]/.test(text(n.tag)) || !Number.isInteger(n.server_port) || Number(n.server_port) < 1 || Number(n.server_port) > 65535 || names.has(text(n.tag))) throw new Error()
      // Local imports are nodes, never routes, DNS, scripts or file-backed transports.
      const tls = n.tls
      const forbidden = ['plugin', 'plugin_opts', 'detour', 'bind_interface', 'routing_mark', 'tls_fragment', 'certificate_path', 'key_path']
      if (forbidden.some(key => key in n) || (record(tls) && ['certificate_path', 'key_path', 'ech'].some(key => key in tls))) throw new Error()
      names.add(text(n.tag)); return n as Outbound
    } catch { throw new Error(`第 ${index + 1} 个节点格式不受支持、名称重复或参数无效；未导入任何节点`) }
  })
}
