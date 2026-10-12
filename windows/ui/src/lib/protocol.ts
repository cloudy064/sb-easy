export interface HelloResult {
  protocol_version: 1
  service_version: string
  supported_methods: string[]
}

export interface ProfileSummary {
  id: string
  name: string
}

export interface ConfigMetadata {
  candidate_available: boolean
  downloaded_etag: string | null
  active_etag: string | null
  last_good_etag?: string | null
  rule_source: string | null
}

export interface DeviceMetadata {
  host_name?: string | null
  server_origin?: string | null
  profile?: ProfileSummary | null
  config?: ConfigMetadata | null
  error?: { code: string; message: string }
}

export interface EnrollmentResult extends DeviceMetadata {
  enrolled: boolean
  phase: string
}

export interface StatusResult extends DeviceMetadata {
  phase: string
  enrolled: boolean
  core_running: boolean
  connection_available: boolean
  tun_active?: boolean
  ipv6?: { checked: boolean; global_address: boolean; native_route: boolean; tun_route: boolean; node_support: 'untested' }
  runtime_error?: { code: string; message: string }
}

export interface SubscriptionSource { id: string; name: string; tags: string[] }
export interface SubscriptionsSummary { managed: SubscriptionSource[]; local: SubscriptionSource[]; sources_available: boolean }

export interface ConfigSummary extends ConfigMetadata {
  subscriptions?: SubscriptionsSummary
  routing_groups?: RoutingGroup[]
  routing_live?: boolean
  gpt_use_default?: boolean
  gpt_outbound?: string | null
  profile: ProfileSummary | null
  counts: { inbounds: number; outbounds: number; rules: number }
  validation?: ConfigValidation
}

export interface RoutingGroup {
  id: string; label: string; server_outbound: string; outbound: string
  mode: 'server' | 'default' | 'node'; editable: boolean; reason: string
}

export interface ConfigValidation {
  state: 'unavailable' | 'not_checked' | 'valid' | 'invalid'
  checked_etag: string | null
  core_version: string
  error?: { code: string; message: string }
}
export interface ProxyNode {
  tag: string; type: string; selected: string; members: string[]; member_count: number; delay?: number | null
}
export interface ConfigCatalog {
  etag: string; final: string; node_count: number; rule_count: number
  nodes: ProxyNode[]
  rules: { index: number; title?: string; match: string; action: string; outbound: string }[]
  inbounds: { type: string; listen: string; port: number; auto_route: boolean }[]
}
export interface ConfigInspection { routing_warning?: boolean; candidate: ConfigCatalog | null; active: ConfigCatalog | null }
export interface RuntimeConnection {
  id: string; host: string; destination: string; port: string; network: string; type: string
  process: string; rule: string; chains: string[]; upload: number; download: number
}
export interface RuntimeSnapshot {
  running: boolean; core_pid: number; sample_ms: number; etag: string | null
  upload_total: number; download_total: number; connection_count: number
  connections: RuntimeConnection[]; nodes: ProxyNode[]
}

export interface TrafficRow { app: string; host: string; outbound: string; rule: string; upload: number; download: number; last_seen: number }
export interface TrafficSnapshot { version: 1; upload: number; download: number; sampled_at: number; cleared_at: number; limited: boolean; storage_ok: boolean; rows: TrafficRow[] }
export interface CaptureConfig {
  enabled: boolean; apps: string[]; domains: string[]; hosts: string[]; bpf: string
  file_kb: number; quota_mb: number; rotate_seconds: number; auto_upload: boolean
  wifi_only: boolean; upload_seconds: number; delete_after_upload: boolean
}
export interface CaptureFile { digest: string; size: number; created_at: number; uploaded: boolean }
export interface CaptureSnapshot { config: CaptureConfig; files: CaptureFile[]; running: boolean; packets: number; dropped: number; stored_bytes: number; error: string; upload_status: string; uploading: boolean; apps: string[] }
export type ExtensionId = 'capture' | 'statistics' | 'network-tools' | 'http-debug'
export function isExtensionId(value: unknown): value is ExtensionId { return ['capture','statistics','network-tools','http-debug'].includes(value as string) }
export interface ExtensionInfo { id: ExtensionId; name: string; version: string; installed: boolean; enabled: boolean; running: boolean; failed: boolean }
export interface StoreItem { id: ExtensionId; name: string; version: string; size: number; publisher: string; description: string; permissions: string }
export interface StoreProgress { id: ExtensionId | '';  phase: 'idle' | 'downloading' | 'verifying' | 'installing' | 'complete' | 'failed'; received: number; total: number; error: string }
export interface HttpDebugState { phase: string; error: string; url: string; attached: boolean; domains?: string[] }
export interface ResultMap {
  'httpdebug.start': HttpDebugState
  'httpdebug.stop': HttpDebugState
  'httpdebug.snapshot': HttpDebugState
  'httpdebug.attach': HttpDebugState
  'httpdebug.certificate': { der: string }
  'httpdebug.export': { ready: true }
  'httpdebug.open': { ready: true }
  'httpdebug.trust': { ready: true }
  'httpdebug.untrust': { ready: true }
  'extensions.catalog': { items: StoreItem[] }
  'extensions.install': StoreProgress
  'extensions.progress': StoreProgress
  'extensions.list': { extensions: ExtensionInfo[] }
  'extensions.change': { extensions: ExtensionInfo[] }
  'service.start': { ready: true }
  'capture.snapshot': CaptureSnapshot
  'capture.configure': CaptureSnapshot
  'capture.validate': { config: CaptureConfig }
  'capture.rotate': CaptureSnapshot
  'capture.upload': CaptureSnapshot
  'capture.delete': CaptureSnapshot
  'capture.read': { data: string; offset: number; next: number; total: number }

  'traffic.snapshot': TrafficSnapshot
  'traffic.clear': TrafficSnapshot
  'logs.snapshot': { lines: string[] }

  'protocol.hello': HelloResult
  'enrollment.status': EnrollmentResult
  'status.get': StatusResult
  'enrollment.apply': EnrollmentResult
  'enrollment.forget': EnrollmentResult
  'config.summary': ConfigSummary
  'config.refresh': ConfigSummary
  'config.validate': ConfigSummary
  'routing.gpt_default': ConfigSummary
  'routing.gpt_server': ConfigSummary
  'routing.gpt_node': ConfigSummary
  'routing.set': ConfigSummary
  'subscriptions.fetch': { body: string }
  'subscriptions.save': ConfigSummary
  'subscriptions.remove': ConfigSummary
  'connection.start': StatusResult
  'connection.stop': StatusResult
  'config.inspect': ConfigInspection
  'runtime.snapshot': RuntimeSnapshot
}

export type Method = keyof ResultMap
export type EmptyParams = Record<string, never>
export type ParamsMap = { [M in Method]: M extends 'httpdebug.attach' ? { domains: string[] } : M extends 'extensions.install' ? { id: ExtensionId } : M extends 'extensions.change' ? { id: ExtensionId; action: 'enable' | 'disable' | 'remove' } : M extends 'subscriptions.fetch' ? ({ url: string } | { id: string }) : M extends 'subscriptions.save' ? { id?: string; name: string; url?: string; nodes: Record<string, unknown>[] } : M extends 'subscriptions.remove' ? { id: string } : M extends 'routing.set' ? ({ group: string; mode: 'server' | 'default' } | { group: string; mode: 'node'; node: string }) : M extends 'routing.gpt_node' ? { outbound: string } : M extends 'enrollment.apply' ? { uri: string } : M extends 'capture.configure' | 'capture.validate' ? { config: CaptureConfig } : M extends 'capture.upload' | 'capture.delete' ? { digest: string } : M extends 'capture.read' ? { digest: string; offset: number } : EmptyParams }

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function boundedString(value: unknown, maxLength: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength
}

function nullableString(value: unknown, maxLength: number): boolean {
  return value === null || (typeof value === 'string' && value.length <= maxLength)
}

function validProfile(value: unknown): boolean {
  return value === null || (isRecord(value) && nullableString(value.id, 256) && typeof value.id === 'string' &&
    typeof value.name === 'string' && value.name.length <= 512)
}

function validConfigMetadata(value: unknown): boolean {
  return isRecord(value) && typeof value.candidate_available === 'boolean' &&
    nullableString(value.downloaded_etag, 1024) && nullableString(value.active_etag, 1024) &&
    (value.last_good_etag === undefined || nullableString(value.last_good_etag, 1024)) &&
    nullableString(value.rule_source, 256)
}

function validValidation(value: unknown): boolean {
  return isRecord(value) && typeof value.state === 'string' && ['unavailable', 'not_checked', 'valid', 'invalid'].includes(value.state) &&
    nullableString(value.checked_etag, 1024) && boundedString(value.core_version, 128) &&
    (value.error === undefined || (isRecord(value.error) && boundedString(value.error.code, 128) && boundedString(value.error.message, 2048)))
}

function validDeviceMetadata(value: Record<string, unknown>): boolean {
  return (value.host_name === undefined || nullableString(value.host_name, 512)) &&
    (value.server_origin === undefined || nullableString(value.server_origin, 4096)) &&
    (value.profile === undefined || validProfile(value.profile)) &&
    (value.config === undefined || value.config === null || validConfigMetadata(value.config)) &&
    (value.error === undefined || (isRecord(value.error) && boundedString(value.error.code, 128) && boundedString(value.error.message, 2048)))
}

export function validParams<M extends Method>(method: M, value: unknown): value is ParamsMap[M] {
  if (!isRecord(value)) return false
  if (method === 'subscriptions.fetch') return Object.keys(value).length === 1 && (boundedString(value.url, 8192) || boundedString(value.id, 36))
  if (method === 'subscriptions.remove') return Object.keys(value).length === 1 && boundedString(value.id, 36)
  if (method === 'subscriptions.save') return Object.keys(value).every(key => ['id','name','url','nodes'].includes(key)) && boundedString(value.name, 100) && (value.id === undefined || boundedString(value.id, 36)) && (value.url === undefined ? boundedString(value.id,36) : boundedString(value.url,8192)) && Array.isArray(value.nodes) && value.nodes.length > 0 && value.nodes.length <= 256 && value.nodes.every(isRecord)
  if (method === 'httpdebug.attach') return Object.keys(value).length === 1 && Array.isArray(value.domains) && value.domains.length > 0 && value.domains.length <= 64 && value.domains.every(d => typeof d === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$/.test(d))
  if (['httpdebug.start','httpdebug.stop','httpdebug.snapshot','httpdebug.certificate','httpdebug.open','httpdebug.export','httpdebug.trust','httpdebug.untrust'].includes(method)) return Object.keys(value).length === 0
  if (method === 'extensions.install') return Object.keys(value).length === 1 && isExtensionId(value.id)
  if (method === 'extensions.change') return Object.keys(value).length === 2 && isExtensionId(value.id) && ['enable','disable','remove'].includes(value.action as string)
  if (method === 'routing.set') return typeof value.group === 'string' && /^[a-z0-9-]{1,64}$/.test(value.group) &&
    (value.mode === 'node' ? Object.keys(value).length === 3 && boundedString(value.node, 512) && !/[\u0000-\u001f\u007f]/.test(value.node) && new TextEncoder().encode(value.node).length <= 512 :
      Object.keys(value).length === 2 && (value.mode === 'server' || (value.mode === 'default' && value.group !== 'default')))
  if (method === 'capture.configure' || method === 'capture.validate') return Object.keys(value).length === 1 && validCaptureConfig(value.config)
  if (method === 'capture.upload' || method === 'capture.delete' || method === 'capture.read') return typeof value.digest === 'string' && /^[a-f0-9]{64}$/.test(value.digest) && (method === 'capture.read' ? Object.keys(value).length === 2 && safeCount(value.offset) && value.offset <= 786432 : Object.keys(value).length === 1)
  if (method === 'routing.gpt_node') return Object.keys(value).length === 1 && boundedString(value.outbound, 512) && !/[\u0000-\u001f\u007f]/.test(value.outbound) && new TextEncoder().encode(value.outbound).length <= 512
  if (method === 'enrollment.apply') return Object.keys(value).length === 1 && boundedString(value.uri, 16_384)
  if (!['extensions.catalog', 'extensions.progress', 'extensions.list', 'service.start', 'protocol.hello', 'enrollment.status', 'enrollment.forget', 'status.get', 'config.summary', 'config.refresh', 'config.validate', 'routing.gpt_default', 'routing.gpt_server', 'connection.start', 'connection.stop', 'config.inspect', 'runtime.snapshot', 'traffic.snapshot', 'traffic.clear', 'logs.snapshot', 'capture.snapshot', 'capture.rotate'].includes(method)) return false
  return Object.keys(value).length === 0
}

export function validResult<M extends Method>(method: M, value: unknown): value is ResultMap[M] {
  if (!isRecord(value)) return false
  switch (method) {
    case 'httpdebug.start': case 'httpdebug.stop': case 'httpdebug.snapshot': case 'httpdebug.attach': return ['starting','running','stopped','failed'].includes(value.phase as string) && typeof value.error === 'string' && typeof value.url === 'string' && typeof value.attached === 'boolean'
    case 'httpdebug.certificate': return typeof value.der === 'string' && value.der.length < 32768 && /^[0-9a-f]+$/.test(value.der)
    case 'httpdebug.export': case 'httpdebug.open': case 'httpdebug.trust': case 'httpdebug.untrust': return value.ready === true
    case 'extensions.catalog': return Array.isArray(value.items) && value.items.length <= 16 && value.items.every(e => isRecord(e) && isExtensionId(e.id) && boundedString(e.name,128) && boundedString(e.version,32) && boundedString(e.publisher,128) && boundedString(e.description,512) && boundedString(e.permissions,512) && Number.isSafeInteger(e.size) && (e.size as number) > 0 && (e.size as number) <= 134217728)
    case 'extensions.install':
    case 'extensions.progress': return (isExtensionId(value.id) || (value.phase === 'idle' && value.id === '')) && ['idle','downloading','verifying','installing','complete','failed'].includes(value.phase as string) && Number.isSafeInteger(value.received) && (value.received as number) >= 0 && Number.isSafeInteger(value.total) && (value.total as number) >= (value.phase === 'idle' ? 0 : 1) && (value.received as number) <= (value.total as number) + 1 && typeof value.error === 'string' && value.error.length <= 64
    case 'extensions.list':
    case 'extensions.change': return Array.isArray(value.extensions) && value.extensions.length <= 16 && value.extensions.every(e => isRecord(e) && isExtensionId(e.id) && boundedString(e.name,128) && typeof e.version === 'string' && e.version.length <= 32 && ['installed','enabled','running','failed'].every(k => typeof e[k] === 'boolean'))
    case 'subscriptions.fetch': return typeof value.body === 'string' && value.body.length <= 262144
    case 'service.start': return value.ready === true
    case 'capture.read':
      return typeof value.data === 'string' && value.data.length <= 87384 && /^[A-Za-z0-9+/]*={0,2}$/.test(value.data) &&
        safeCount(value.offset) && safeCount(value.next) && safeCount(value.total) && value.total <= 786432 && value.offset <= value.next && value.next <= value.total && value.next - value.offset <= 65536
    case 'capture.validate': return validCaptureConfig(value.config)
    case 'capture.snapshot':
    case 'capture.configure':
    case 'capture.rotate':
    case 'capture.upload':
    case 'capture.delete':
      return validCaptureConfig(value.config) && typeof value.running === 'boolean' && typeof value.uploading === 'boolean' &&
        ['packets','dropped','stored_bytes'].every(key => safeCount(value[key])) &&
        typeof value.error === 'string' && value.error.length <= 256 && typeof value.upload_status === 'string' && value.upload_status.length <= 256 &&
        Array.isArray(value.apps) && value.apps.length <= 512 && value.apps.every(item => typeof item === 'string' && item.length <= 96) &&
        Array.isArray(value.files) && value.files.length <= 1000 && value.files.every(file => isRecord(file) && typeof file.digest === 'string' && /^[a-f0-9]{64}$/.test(file.digest) && safeCount(file.size) && safeCount(file.created_at) && typeof file.uploaded === 'boolean')
    case 'logs.snapshot':
      return Array.isArray(value.lines) && value.lines.length <= 200 && value.lines.every(line => typeof line === 'string' && line.length <= 1024)
    case 'traffic.snapshot':
    case 'traffic.clear':
      return value.version === 1 && ['upload', 'download', 'sampled_at', 'cleared_at'].every(key => safeCount(value[key])) &&
        typeof value.limited === 'boolean' && typeof value.storage_ok === 'boolean' && Array.isArray(value.rows) && value.rows.length <= 512 &&
        value.rows.every(row => isRecord(row) && ['app', 'host', 'outbound', 'rule'].every(key => typeof row[key] === 'string' && (row[key] as string).length <= 253) &&
          ['upload', 'download', 'last_seen'].every(key => safeCount(row[key])))
    case 'config.inspect':
      return (value.routing_warning === undefined || typeof value.routing_warning === 'boolean') && validCatalog(value.candidate) && validCatalog(value.active)
    case 'runtime.snapshot':
      return typeof value.running === 'boolean' && safeCount(value.core_pid) && safeCount(value.sample_ms) &&
        nullableString(value.etag, 4096) && safeCount(value.upload_total) && safeCount(value.download_total) && safeCount(value.connection_count) &&
        Array.isArray(value.connections) && value.connections.length <= 128 && value.connections.every(validConnection) &&
        Array.isArray(value.nodes) && value.nodes.length <= 1024 && value.nodes.every(validNode)
    case 'protocol.hello':
      return value.protocol_version === 1 && boundedString(value.service_version, 128) &&
        Array.isArray(value.supported_methods) && value.supported_methods.length <= 128 &&
        value.supported_methods.every(item => boundedString(item, 128))
    case 'enrollment.status':
    case 'enrollment.apply':
    case 'enrollment.forget':
      return typeof value.enrolled === 'boolean' && boundedString(value.phase, 64) && validDeviceMetadata(value)
    case 'status.get':
    case 'connection.start':
    case 'connection.stop':
      return boundedString(value.phase, 64) && typeof value.enrolled === 'boolean' &&
        typeof value.core_running === 'boolean' && typeof value.connection_available === 'boolean' && validDeviceMetadata(value) &&
        (value.tun_active === undefined || typeof value.tun_active === 'boolean') &&
        (value.ipv6 === undefined || (isRecord(value.ipv6) &&
          ['checked', 'global_address', 'native_route', 'tun_route'].every(key => typeof (value.ipv6 as Record<string, unknown>)[key] === 'boolean') &&
          value.ipv6.node_support === 'untested')) &&
        (value.runtime_error === undefined || (isRecord(value.runtime_error) && boundedString(value.runtime_error.code, 128) && boundedString(value.runtime_error.message, 2048)))
    case 'config.summary':
    case 'config.refresh':
    case 'routing.gpt_default':
    case 'routing.gpt_server':
    case 'routing.gpt_node':
    case 'subscriptions.save':
    case 'subscriptions.remove':
    case 'routing.set':
    case 'config.validate':
      return (value.subscriptions === undefined || (isRecord(value.subscriptions) && typeof value.subscriptions.sources_available === 'boolean' && ['managed','local'].every(key => { const list = (value.subscriptions as Record<string, unknown>)[key]; return Array.isArray(list) && list.length <= 1024 && list.every(sub => isRecord(sub) && boundedString(sub.id,128) && boundedString(sub.name,1024) && Array.isArray(sub.tags) && sub.tags.length <= 1024 && sub.tags.every(tag => boundedString(tag,512))) }))) && (value.routing_live === undefined || typeof value.routing_live === 'boolean') &&
        (value.routing_groups === undefined || (Array.isArray(value.routing_groups) && value.routing_groups.length <= 64 && value.routing_groups.every(g => isRecord(g) &&
          boundedString(g.id,64) && boundedString(g.label,512) && nullableString(g.server_outbound,512) && nullableString(g.outbound,512) &&
          ['server','default','node'].includes(g.mode as string) && typeof g.editable === 'boolean' && typeof g.reason === 'string'))) &&
        (value.gpt_outbound === undefined || nullableString(value.gpt_outbound, 512)) && (value.gpt_use_default === undefined || typeof value.gpt_use_default === 'boolean') && validConfigMetadata(value) && validProfile(value.profile) && isRecord(value.counts) &&
        (value.validation === undefined || validValidation(value.validation)) &&
        ['inbounds', 'outbounds', 'rules'].every(key => {
          const count = (value.counts as Record<string, unknown>)[key]
          return typeof count === 'number' && Number.isSafeInteger(count) && count >= 0
        })
  }
  return false
}

function safeCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}
function displayString(value: unknown): value is string { return typeof value === 'string' && value.length <= 128 && !value.includes('\0') }
function displayStrings(value: unknown, max: number): boolean {
  return Array.isArray(value) && value.length <= max && value.every(displayString)
}
function validNode(value: unknown): boolean {
  return isRecord(value) && ['tag', 'type', 'selected'].every(key => displayString(value[key])) &&
    displayStrings(value.members, 16) && safeCount(value.member_count) &&
    (value.delay === undefined || value.delay === null || (safeCount(value.delay) && value.delay <= 65535))
}
function validCatalog(value: unknown): boolean {
  return value === null || (isRecord(value) && nullableString(value.etag, 4096) && typeof value.etag === 'string' && displayString(value.final) &&
    safeCount(value.node_count) && safeCount(value.rule_count) && Array.isArray(value.nodes) && value.nodes.length <= 1024 && value.nodes.every(validNode) &&
    Array.isArray(value.inbounds) && value.inbounds.length <= 16 && value.inbounds.every(item => isRecord(item) && displayString(item.type) && displayString(item.listen) && safeCount(item.port) && typeof item.auto_route === 'boolean') &&
    Array.isArray(value.rules) && value.rules.length <= 128 && value.rules.every(item => isRecord(item) && safeCount(item.index) && (item.title === undefined || displayString(item.title)) && typeof item.match === 'string' && item.match.length <= 600 && displayString(item.action) && displayString(item.outbound)))
}
function validConnection(value: unknown): boolean {
  return isRecord(value) && ['id', 'host', 'destination', 'port', 'network', 'type', 'process', 'rule'].every(key => displayString(value[key])) &&
    displayStrings(value.chains, 8) && safeCount(value.upload) && safeCount(value.download)
}

export function validCaptureConfig(value: unknown): value is CaptureConfig {
  if (!isRecord(value)) return false
  if (!['enabled','auto_upload','wifi_only','delete_after_upload'].every(key => typeof value[key] === 'boolean')) return false
  if (!['apps','domains','hosts'].every(key => Array.isArray(value[key]) && (value[key] as unknown[]).length <= 100 && (value[key] as unknown[]).every(item => typeof item === 'string' && item.length > 0 && item.length <= (key === 'apps' ? 96 : 253) && !/[\x00-\x1f]/.test(item)))) return false
  return typeof value.bpf === 'string' && value.bpf.length <= 4096 && !value.bpf.includes('\0') &&
    [['file_kb',128,768],['quota_mb',8,256],['rotate_seconds',10,600],['upload_seconds',30,3600]].every(([key,low,high]) => safeCount(value[key as string]) && (value[key as string] as number) >= Number(low) && (value[key as string] as number) <= Number(high))
}
