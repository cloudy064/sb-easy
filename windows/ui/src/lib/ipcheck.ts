export interface IpCheckCatalog {
  nodes: { tag: string; type: string; source?: string }[]
  interfaces: { name: string }[]
  default_interface: string
}

export interface DailyIpEntry {
  status: 'ok' | 'failed' | 'pending' | 'refreshing' | 'disabled' | 'unsupported'
  attempted_at: number | null
  next_check_at: number | null
  result: Partial<IpCheckResult> | null
  last_success: Partial<IpCheckResult> | null
}
export interface DailyIpCache {
  nodes: Record<string, DailyIpEntry>
  running: boolean
  error: string
  interval_seconds: number
}
export function validDailyIpCache(value: unknown): value is DailyIpCache {
  const validTime = (v: unknown) => v === null || typeof v === 'number' && Number.isFinite(v) && v >= 0
  const validResult = (v: unknown) => v === null || record(v) && optionalText(v.checked_at, 64) &&
    optionalText(v.reason, 128) && (v.ipv4 === undefined || validMeasurement(v.ipv4)) && (v.ipv6 === undefined || validMeasurement(v.ipv6))
  return record(value) && record(value.nodes) && Object.keys(value.nodes).length <= 2048 &&
    typeof value.running === 'boolean' && text(value.error, 512) && count(value.interval_seconds, 604800) && value.interval_seconds > 0 &&
    Object.entries(value.nodes).every(([tag, entry]) => text(tag, 512, false) && record(entry) &&
      ['ok','failed','pending','refreshing','disabled','unsupported'].includes(entry.status as string) &&
      validTime(entry.attempted_at) && validTime(entry.next_check_at) && validResult(entry.result) && validResult(entry.last_success))
}
export function dailyMeasurement(entry?: DailyIpEntry): Partial<IpCheckResult> | null | undefined {
  return entry?.result?.ipv4?.ip || entry?.result?.ipv6?.ip ? entry.result : entry?.last_success || entry?.result
}

export interface IpInfoFields {
  country?: string | null
  country_code?: string | null
  region?: string | null
  city?: string | null
  asn?: string | null
  organization?: string | null
  organization_en?: string | null
  isp?: string | null
  domain?: string | null
  is_anycast?: boolean | null
  privacy?: { type?: string | null; is_datacenter?: boolean | null; is_vpn?: boolean | null; is_anonymous?: boolean | null; is_icloud_relay?: boolean | null; is_tor?: boolean | null; is_known_bot?: boolean | null }
  proxy_intelligence?: { is_proxy?: boolean | null; source_count?: number | null; first_seen?: string | null; last_seen?: string | null; active_days_7d?: number | null; active_days_30d?: number | null; active_days_90d?: number | null; num_days_seen?: number | null }
  threat_intelligence?: { is_threat?: boolean | null; first_seen?: string | null; last_seen?: string | null; active_days_30d?: number | null; recent_abuse?: string[] | null; history_abuse?: string[] | null }
}

export interface IpDataSource {
  id: string
  name: string
  url: string
  license: string
  updated_at?: string | null
  retrieved_at?: string | null
  status: 'ready' | 'missing' | 'stale' | 'invalid'
  families: number[]
}
export interface IpListCheck {
  id: 'datacenter' | 'vpn' | 'tor'
  status: 'listed' | 'not_listed' | 'unavailable' | 'unsupported' | 'stale'
  source: string
  network?: string | null
  updated_at?: string | null
}

export interface IpCheckInfo {
  status: 'ok' | 'unknown'
  partial?: boolean
  reason?: string | null
  http_status?: number
  provider?: string
  queried_ip?: string
  checked_at?: string
  fields?: IpInfoFields
  checks?: IpListCheck[]
  sources?: IpDataSource[]
  field_sources?: Partial<Record<'country' | 'country_code' | 'region' | 'city' | 'asn' | 'organization', string>>
  database?: { version: string; generated_at: string }
}
export interface IpCheckMeasurement {
  status: 'ok' | 'unknown'
  ip?: string
  reason?: string
  ip_info?: IpCheckInfo
  ip_info_cached?: boolean
}
export interface IpCheckResult {
  node: string
  checked_at: string
  ipv6_requested: boolean
  status?: 'unknown'
  reason?: string
  ipv4?: IpCheckMeasurement
  ipv6?: IpCheckMeasurement
}
export interface IpCheckState {
  phase: 'idle' | 'running' | 'complete' | 'partial' | 'failed' | 'cancelled'
  results: IpCheckResult[]
  summary: { status: 'complete' | 'partial' | 'failed'; node_count: number; processed_count: number; measured_count: number; info_count: number; complete_count: number }
  error: string
  cancel_requested?: boolean
}

const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)
const text = (value: unknown, max: number, empty = true): value is string => typeof value === 'string' && value.length <= max && (empty || value.length > 0) && !/[\u0000-\u001f\u007f]/.test(value)
const count = (value: unknown, max = 100): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max
const optionalText = (value: unknown, max = 512): boolean => value === undefined || value === null || text(value, max)
const optionalFlag = (value: unknown): boolean => value === undefined || value === null || typeof value === 'boolean'

export function validIpCheckStart(value: unknown): boolean {
  return record(value) && Object.keys(value).length === 2 && Array.isArray(value.tags) && value.tags.length > 0 && value.tags.length <= 100 &&
    value.tags.every(tag => text(tag, 256, false) && new TextEncoder().encode(tag).length <= 256) && new Set(value.tags).size === value.tags.length &&
    typeof value.ipv6 === 'boolean'
}

export function validIpCheckCatalog(value: unknown): value is IpCheckCatalog {
  return record(value) && Array.isArray(value.nodes) && value.nodes.length <= 2048 &&
    value.nodes.every(node => record(node) && text(node.tag, 512, false) && text(node.type, 64, false) && (node.source === undefined || text(node.source, 1024))) &&
    new Set(value.nodes.map(node => node.tag)).size === value.nodes.length &&
    Array.isArray(value.interfaces) && value.interfaces.length <= 128 && value.interfaces.every(item => record(item) && text(item.name, 256, false)) &&
    text(value.default_interface, 256) && (value.default_interface === '' || value.interfaces.some(item => item.name === value.default_interface))
}

function validFields(value: unknown): boolean {
  if (!record(value)) return false
  if (!['country', 'country_code', 'region', 'city', 'asn', 'organization', 'organization_en', 'isp', 'domain'].every(key => optionalText(value[key]))) return false
  if (!optionalFlag(value.is_anycast)) return false
  for (const key of ['privacy', 'proxy_intelligence', 'threat_intelligence']) {
    const section = value[key]
    if (section === undefined) continue
    if (!record(section)) return false
    for (const [field, item] of Object.entries(section)) {
      if (field.startsWith('is_')) { if (!optionalFlag(item)) return false }
      else if (field === 'recent_abuse' || field === 'history_abuse') {
        if (item !== null && (!Array.isArray(item) || item.length > 100 || !item.every(entry => text(entry, 512)))) return false
      } else if (['source_count', 'active_days_7d', 'active_days_30d', 'active_days_90d', 'num_days_seen'].includes(field)) {
        if (item !== null && !count(item, Number.MAX_SAFE_INTEGER)) return false
      } else if (!optionalText(item)) return false
    }
  }
  return true
}

function validInfo(value: unknown): boolean {
  if (!record(value) || !['ok', 'unknown'].includes(value.status as string)) return false
  if (value.partial !== undefined && typeof value.partial !== 'boolean') return false
  if (value.sources !== undefined && (!Array.isArray(value.sources) || value.sources.length > 16 || !value.sources.every(source => record(source) &&
    text(source.id, 64, false) && text(source.name, 256, false) && text(source.url, 1024, false) && /^https:\/\//.test(source.url) &&
    text(source.license, 256, false) && optionalText(source.updated_at, 64) && optionalText(source.retrieved_at, 64) &&
    ['ready', 'missing', 'stale', 'invalid'].includes(source.status as string) && Array.isArray(source.families) && source.families.length <= 2 &&
    source.families.every(family => family === 4 || family === 6) && new Set(source.families).size === source.families.length) ||
    new Set(value.sources.map(source => source.id)).size !== value.sources.length)) return false
  const sources = value.sources as IpDataSource[] | undefined
  if (value.checks !== undefined && (!Array.isArray(value.checks) || value.checks.length > 3 || !value.checks.every(check => record(check) &&
    ['datacenter', 'vpn', 'tor'].includes(check.id as string) && ['listed', 'not_listed', 'unavailable', 'unsupported', 'stale'].includes(check.status as string) &&
    text(check.source, 64, false) && sources?.some(source => source.id === check.source) && optionalText(check.network, 64) && optionalText(check.updated_at, 64)) ||
    new Set(value.checks.map(check => check.id)).size !== value.checks.length)) return false
  if (value.database !== undefined && (!record(value.database) || !text(value.database.version, 64, false) || !text(value.database.generated_at, 64, false))) return false
  if (value.field_sources !== undefined && (!record(value.field_sources) || !Object.entries(value.field_sources).every(([field, source]) =>
    ['country', 'country_code', 'region', 'city', 'asn', 'organization'].includes(field) && text(source, 64, false) && sources?.some(item => item.id === source)))) return false
  if (value.provider === 'sb-easy-offline') {
    if (!Array.isArray(value.checks) || !Array.isArray(value.sources)) return false
    const privacy = record(value.fields) && record(value.fields.privacy) ? value.fields.privacy : undefined
    if (privacy && !['is_datacenter', 'is_vpn', 'is_tor'].every(key => privacy[key] === undefined || privacy[key] === null || privacy[key] === true)) return false
  }
  return optionalText(value.reason, 128) && optionalText(value.provider, 64) && optionalText(value.queried_ip, 64) && optionalText(value.checked_at, 64) &&
    (value.http_status === undefined || (count(value.http_status, 599) && value.http_status >= 100)) &&
    (value.status === 'ok' ? validFields(value.fields) : value.fields === undefined || validFields(value.fields))
}

function validMeasurement(value: unknown): boolean {
  if (!record(value) || !['ok', 'unknown'].includes(value.status as string)) return false
  return (value.status === 'ok' ? text(value.ip, 64, false) : value.ip === undefined) && optionalText(value.reason, 128) &&
    (value.ip_info === undefined || validInfo(value.ip_info)) && (value.ip_info_cached === undefined || typeof value.ip_info_cached === 'boolean')
}

export function validIpCheckState(value: unknown): value is IpCheckState {
  if (!record(value) || !['idle', 'running', 'complete', 'partial', 'failed', 'cancelled'].includes(value.phase as string) || !text(value.error, 512)) return false
  if (value.cancel_requested !== undefined && typeof value.cancel_requested !== 'boolean') return false
  if (!Array.isArray(value.results) || value.results.length > 100 || !value.results.every(result => record(result) && text(result.node, 512, false) &&
    text(result.checked_at, 64, false) && typeof result.ipv6_requested === 'boolean' && (result.status === undefined || result.status === 'unknown') &&
    optionalText(result.reason, 128) && (result.ipv4 === undefined || validMeasurement(result.ipv4)) && (result.ipv6 === undefined || validMeasurement(result.ipv6)))) return false
  const summary = value.summary
  if (!record(summary) || !['complete', 'partial', 'failed'].includes(summary.status as string) ||
    !['node_count', 'processed_count', 'measured_count', 'info_count', 'complete_count'].every(key => count(summary[key]))) return false
  return summary.processed_count === value.results.length && (summary.processed_count as number) <= (summary.node_count as number) &&
    (summary.measured_count as number) <= (summary.processed_count as number) && (summary.info_count as number) <= (summary.measured_count as number) &&
    (summary.complete_count as number) <= (summary.info_count as number)
}

export function infoLabel(info?: IpCheckInfo): string {
  if (!info) return '资料未获取'
  if (info.provider === 'sb-easy-offline') return info.status === 'ok' && !info.partial ? '中心公开数据' : '中心公开数据 · 部分资料未知'
  if (info.status === 'ok') return '历史数据源资料'
  if (info.http_status === 403 || info.reason === 'blocked') return '资料接口拒绝（403）'
  if (info.http_status === 429 || info.reason === 'rate_limited') return '资料接口限流（429）'
  if (info.reason === 'timeout' || info.reason === 'network_error') return '资料查询未连通'
  return '资料暂不可用'
}

export function listCheckLabel(check?: IpListCheck): string {
  if (!check) return '未知'
  return { listed: '命中名单', not_listed: '未命中此名单', unavailable: '名单不可用', unsupported: '此名单不支持该地址类型', stale: '名单已过期，结果未知' }[check.status]
}

export function dataSourceStatus(source: IpDataSource): string {
  return { ready: '可用', missing: '未安装', stale: '已过期', invalid: '校验失败' }[source.status]
}

export function sourceDate(value?: string | null): string {
  if (!value) return '日期未知'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? '日期未知' : parsed.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' })
}

export function fieldSourceLabel(source?: IpDataSource): string {
  if (!source) return ''
  return `${source.name} · ${sourceDate(source.updated_at)}${source.status === 'ready' ? '' : ` · ${dataSourceStatus(source)}`}`
}

export function sourceForField(info: IpCheckInfo, field: 'country' | 'asn' | 'organization'): IpDataSource | undefined {
  const id = info.field_sources?.[field] ?? (field === 'country' ? info.field_sources?.country_code : undefined)
  return info.sources?.find(source => source.id === (id ?? (field === 'country' ? 'geo' : 'asn')))
}

export function sourceForCheck(info: IpCheckInfo, check: IpListCheck): IpDataSource | undefined {
  return info.sources?.find(source => source.id === check.source)
}

export function flagLabel(value: boolean | null | undefined): string {
  return value === true ? '是' : value === false ? '否' : '未知'
}

export function measurementLabel(measurement?: IpCheckMeasurement, family = 4, requested = true): string {
  if (!requested) return '未检测'
  if (measurement?.status === 'ok') return measurement.ip ?? '未知'
  return family === 6 ? '本次 IPv6 路径未成功' : '未测得出口 IP'
}

export function probeErrorLabel(code?: string): string {
  const labels: Record<string, string> = {
    physical_interface_required: '请选择本机联网网卡',
    unsupported_proxy_type: '暂不支持此节点类型',
    unsupported_urltest_dependency: '节点依赖自动选择组，暂不能单独检测',
    probe_core_start_failed: '检测通道启动失败',
    probe_core_start_timeout: '检测通道启动超时',
    echo_connection_failed: '出口检测请求未连通',
    echo_http_error: '出口检测服务返回错误',
    probe_runtime_io_failed: '检测进程未能完成',
    probe_worker_stopped: '检测进程已停止，可以重新开始',
    probe_runtime_failed: '检测进程运行失败，请重试',
  }
  return code ? labels[code] ?? `检测未完成（${code}）` : '检测未完成'
}
