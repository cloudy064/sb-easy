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
  runtime_error?: { code: string; message: string }
}

export interface ConfigSummary extends ConfigMetadata {
  profile: ProfileSummary | null
  counts: { inbounds: number; outbounds: number; rules: number }
  validation?: ConfigValidation
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
  rules: { index: number; match: string; action: string; outbound: string }[]
  inbounds: { type: string; listen: string; port: number; auto_route: boolean }[]
}
export interface ConfigInspection { candidate: ConfigCatalog | null; active: ConfigCatalog | null }
export interface RuntimeConnection {
  id: string; host: string; destination: string; port: string; network: string; type: string
  process: string; rule: string; chains: string[]; upload: number; download: number
}
export interface RuntimeSnapshot {
  running: boolean; core_pid: number; sample_ms: number; etag: string | null
  upload_total: number; download_total: number; connection_count: number
  connections: RuntimeConnection[]; nodes: ProxyNode[]
}

export interface ResultMap {
  'protocol.hello': HelloResult
  'enrollment.status': EnrollmentResult
  'status.get': StatusResult
  'enrollment.apply': EnrollmentResult
  'enrollment.forget': EnrollmentResult
  'config.summary': ConfigSummary
  'config.refresh': ConfigSummary
  'config.validate': ConfigSummary
  'connection.start': StatusResult
  'connection.stop': StatusResult
  'config.inspect': ConfigInspection
  'runtime.snapshot': RuntimeSnapshot
}

export type Method = keyof ResultMap
export type EmptyParams = Record<string, never>
export type ParamsMap = { [M in Method]: M extends 'enrollment.apply' ? { uri: string } : EmptyParams }

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
  if (method === 'enrollment.apply') return Object.keys(value).length === 1 && boundedString(value.uri, 16_384)
  if (!['protocol.hello', 'enrollment.status', 'enrollment.forget', 'status.get', 'config.summary', 'config.refresh', 'config.validate', 'connection.start', 'connection.stop', 'config.inspect', 'runtime.snapshot'].includes(method)) return false
  return Object.keys(value).length === 0
}

export function validResult<M extends Method>(method: M, value: unknown): value is ResultMap[M] {
  if (!isRecord(value)) return false
  switch (method) {
    case 'config.inspect':
      return validCatalog(value.candidate) && validCatalog(value.active)
    case 'runtime.snapshot':
      return typeof value.running === 'boolean' && safeCount(value.core_pid) && safeCount(value.sample_ms) &&
        nullableString(value.etag, 4096) && safeCount(value.upload_total) && safeCount(value.download_total) && safeCount(value.connection_count) &&
        Array.isArray(value.connections) && value.connections.length <= 128 && value.connections.every(validConnection) &&
        Array.isArray(value.nodes) && value.nodes.length <= 128 && value.nodes.every(validNode)
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
        (value.runtime_error === undefined || (isRecord(value.runtime_error) && boundedString(value.runtime_error.code, 128) && boundedString(value.runtime_error.message, 2048)))
    case 'config.summary':
    case 'config.refresh':
    case 'config.validate':
      return validConfigMetadata(value) && validProfile(value.profile) && isRecord(value.counts) &&
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
    safeCount(value.node_count) && safeCount(value.rule_count) && Array.isArray(value.nodes) && value.nodes.length <= 128 && value.nodes.every(validNode) &&
    Array.isArray(value.inbounds) && value.inbounds.length <= 16 && value.inbounds.every(item => isRecord(item) && displayString(item.type) && displayString(item.listen) && safeCount(item.port) && typeof item.auto_route === 'boolean') &&
    Array.isArray(value.rules) && value.rules.length <= 128 && value.rules.every(item => isRecord(item) && safeCount(item.index) && typeof item.match === 'string' && item.match.length <= 600 && displayString(item.action) && displayString(item.outbound)))
}
function validConnection(value: unknown): boolean {
  return isRecord(value) && ['id', 'host', 'destination', 'port', 'network', 'type', 'process', 'rule'].every(key => displayString(value[key])) &&
    displayStrings(value.chains, 8) && safeCount(value.upload) && safeCount(value.download)
}
