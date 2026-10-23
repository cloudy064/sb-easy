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

export type UsageMode = 'unconfigured' | 'managed' | 'independent'
export interface DeviceMetadata {
  mode?: UsageMode
  managed_available?: boolean
  independent_available?: boolean
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

export interface ManagementSettings {
  auto_connect: boolean
  auto_reconnect: boolean
  telemetry_enabled: boolean
  kill_switch_enabled?: boolean
  sync_interval_seconds: number
}
export interface KillSwitchStatus { available: boolean; enabled: boolean; error_code: string; filter_count: number; tun_allowed: boolean; persistent: boolean }
export interface ManagementStatus extends ManagementSettings {
  kill_switch_preference_known?: boolean
  kill_switch_recovery_required?: boolean
  kill_switch?: KillSwitchStatus
  manual_disconnect: boolean
  desired_connected: boolean
  worker_running: boolean
  retry_attempt: number
  retry_in_seconds: number
  last_sync_at: number
  last_report_at: number
  last_error: string | null
  last_error_code: string | null
}
export interface LocalRoutingGroup {
  id: string; label: string; domains: string[]; processes: string[]
  mode: 'default' | 'node'; node?: string
}
export interface RouteProbeResult {
  url: string; host: string; port: number; success: boolean
  http_status: number; elapsed_ms: number; error_code: string
  evidence: {
    observed: boolean; dns: string; public_exit_ip: string; process_scope: string; logs: string[]
    connection?: { id: string; rule: string; metadata: Record<string, string>; chains: string[] }
  }
}
export interface RouteDelayResult { target: string; url: string; delay_ms: number; success: boolean }
export interface PreferencesEnvelope { format: 'sb-easy.preferences'; version: 1; kdf: 'pbkdf2-sha256'; iterations: 600000; salt: string; nonce: string; ciphertext: string }
export interface PreferencesPreview { preview_id: string; expires_in_seconds: number; subscription_names: string[]; node_count: number; routing_count: number; device_settings_preserved: true }
export interface PreferencesCloud { connected: boolean; mfa_required: boolean; server: string; username: string; session_id: string; revision_known: boolean; revision: number; envelope?: PreferencesEnvelope | null; updated_at?: number; deleted?: boolean }
export type UpdatePhase = 'unavailable' | 'idle' | 'checking' | 'available' | 'current' | 'deferred' | 'downloading' | 'ready' | 'installing' | 'succeeded' | 'rolled_back' | 'failed' | 'cancelled' | 'recovery_required'
export interface UpdateStatus {
  supported: boolean; installed_service: boolean; publisher_configured: boolean; current_version: string; current_core_version: string
  phase: UpdatePhase; busy: boolean; cancellable: boolean; received_bytes: number
  release?: { id: string; version: string; core_version: string; channel: 'stable'; bytes: number; rollout_percent: number }
  error?: { code: string; message: string }
  last_result?: { phase: 'installing' | 'succeeded' | 'rolled_back' | 'failed' | 'recovery_required'; version: string; installer_code: number; reboot_required: boolean; state_restored: boolean; error_code: string }
}
export interface HealthPolicy {
  enabled: boolean; probe_url: string; interval_seconds: number; timeout_millis: number; tolerance_millis: number
  selection: 'failover' | 'fastest'
}
export interface HealthSnapshot {
  running: boolean; checking: boolean; checked_at: number; completed: number; total: number; error_code: string
  results: { tag: string; success: boolean; delay_ms: number | null; error_code: string }[]
  groups: { id: string; selected: string; automatic: boolean; error_code: string }[]
}
export interface StatusResult extends DeviceMetadata {
  management?: ManagementStatus
  phase: string
  enrolled: boolean
  core_running: boolean
  connection_available: boolean
  tun_active?: boolean
  ipv6?: { checked: boolean; global_address: boolean; native_route: boolean; tun_route: boolean; node_support: 'untested' }
  runtime_error?: { code: string; message: string }
}

export interface SubscriptionSource { id: string; name: string; tags: string[] }
export interface SubscriptionMetadata {
  available: boolean; header_present: boolean
  upload_bytes?: number; download_bytes?: number; total_bytes?: number; used_bytes?: number; remaining_bytes?: number
  expires_at?: number; expired?: boolean; quota_exhausted?: boolean; warning?: string
}
export interface SubscriptionReport { imported: number; skipped: number; format: 'sing-box-json' | 'clash-yaml' | 'uri'; base64: boolean; warnings: { position: number; reason: string }[] }
export interface LocalSubscriptionSource extends SubscriptionSource {
  node_count?: number; remote?: boolean; refresh_interval_minutes?: number
  last_attempt_at?: number; last_success_at?: number; next_refresh_at?: number; last_error?: string
  metadata?: SubscriptionMetadata; report?: Partial<SubscriptionReport>
}
export interface SubscriptionImport { name: string; body?: string; url?: string; id?: string; refresh_interval_minutes?: number }
export interface SubscriptionsSummary { managed: SubscriptionSource[]; local: LocalSubscriptionSource[]; sources_available: boolean }

export interface ConfigSummary extends ConfigMetadata {
  health_policy?: HealthPolicy
  health?: HealthSnapshot
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
  mode: 'server' | 'default' | 'node' | 'automatic'; editable: boolean; reason: string
  automatic_candidates?: string[]
  local?: boolean; domains?: string[]; processes?: string[]; node?: string
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
export interface ExtensionTrust { verified?: boolean; revoked?: boolean; build?: number; update_available?: boolean; rollback_available?: boolean; pending_health?: boolean }
export interface ExtensionInfo extends ExtensionTrust { id: ExtensionId; name: string; version: string; installed: boolean; enabled: boolean; running: boolean; failed: boolean }
export interface StoreCatalog { items: StoreItem[]; trust_configured?: boolean; catalog_fresh?: boolean; sequence?: number }
export interface StoreItem extends ExtensionTrust { installed_version?: string; available_build?: number; catalog_fresh?: boolean; install_available?: boolean; id: ExtensionId; name: string; version: string; size: number; publisher: string; description: string; permissions: string }
export interface StoreProgress { id: ExtensionId | '';  phase: 'idle' | 'downloading' | 'verifying' | 'ready' | 'installing' | 'complete' | 'failed'; received: number; total: number; error: string }
export interface HttpDebugState { phase: string; error: string; url: string; attached: boolean; domains?: string[] }
export interface ResultMap {
  'updates.status': UpdateStatus
  'updates.check': UpdateStatus
  'updates.download': UpdateStatus
  'updates.install': UpdateStatus
  'updates.cancel': UpdateStatus
  'updates.recover': UpdateStatus
  'httpdebug.start': HttpDebugState
  'httpdebug.stop': HttpDebugState
  'httpdebug.snapshot': HttpDebugState
  'httpdebug.attach': HttpDebugState
  'httpdebug.certificate': { der: string }
  'httpdebug.export': { ready: true }
  'httpdebug.open': { ready: true }
  'httpdebug.trust': { ready: true }
  'httpdebug.untrust': { ready: true }
  'extensions.catalog': StoreCatalog
  'extensions.catalog_update': StoreCatalog
  'extensions.rollback': { extensions: ExtensionInfo[] }
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
  'routing.group_save': ConfigSummary
  'routing.group_remove': ConfigSummary
  'routing.probe': RouteProbeResult
  'routing.delay': RouteDelayResult
  'preferences.export': { envelope: PreferencesEnvelope }
  'preferences.preview': PreferencesPreview
  'preferences.apply': ConfigSummary
  'preferences.cloud.login': PreferencesCloud
  'preferences.cloud.mfa': PreferencesCloud
  'preferences.cloud.logout': PreferencesCloud
  'preferences.cloud.get': PreferencesCloud
  'preferences.cloud.put': PreferencesCloud
  'preferences.cloud.delete': PreferencesCloud
  'routing.health.set': ConfigSummary
  'routing.health.check': ConfigSummary
  'routing.automatic.set': ConfigSummary
  'mode.set': StatusResult
  'subscriptions.import': ConfigSummary
  'subscriptions.refresh': ConfigSummary
  'management.settings.get': ManagementStatus
  'management.settings.set': ManagementStatus
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
export type ParamsMap = { [M in Method]: M extends 'updates.check' ? { manifest_url: string } : M extends 'updates.download' | 'updates.install' ? { release_id: string } : M extends 'preferences.export' ? { password: string } : M extends 'preferences.preview' ? { password: string; envelope: PreferencesEnvelope } : M extends 'preferences.apply' ? { preview_id: string } : M extends 'preferences.cloud.login' ? { server: string; username: string; password: string } : M extends 'preferences.cloud.mfa' ? { session_id: string; code: string } : M extends 'preferences.cloud.logout' | 'preferences.cloud.get' ? { session_id: string } : M extends 'preferences.cloud.put' ? { session_id: string; password: string; revision: number } : M extends 'preferences.cloud.delete' ? { session_id: string; revision: number } : M extends 'routing.health.set' ? HealthPolicy : M extends 'routing.automatic.set' ? { group: string; candidates: string[] } : M extends 'mode.set' ? { mode: 'managed' | 'independent' } : M extends 'subscriptions.import' ? { name: string; body?: string; url?: string; id?: string; refresh_interval_minutes?: number } : M extends 'subscriptions.refresh' ? { id: string } : M extends 'management.settings.set' ? Partial<ManagementSettings> : M extends 'routing.group_save' ? LocalRoutingGroup : M extends 'routing.group_remove' ? { id: string } : M extends 'routing.probe' ? { url: string; timeout_ms?: number } : M extends 'routing.delay' ? { target: string; url?: string; timeout_ms?: number } : M extends 'httpdebug.attach' ? { domains: string[] } : M extends 'extensions.catalog_update' ? { envelope: string } : M extends 'extensions.install' | 'extensions.rollback' ? { id: ExtensionId } : M extends 'extensions.change' ? { id: ExtensionId; action: 'enable' | 'disable' | 'remove' } : M extends 'subscriptions.fetch' ? ({ url: string } | { id: string }) : M extends 'subscriptions.save' ? { id?: string; name: string; url?: string; nodes: Record<string, unknown>[] } : M extends 'subscriptions.remove' ? { id: string } : M extends 'routing.set' ? ({ group: string; mode: 'server' | 'default' } | { group: string; mode: 'node'; node: string }) : M extends 'routing.gpt_node' ? { outbound: string } : M extends 'enrollment.apply' ? { uri: string } : M extends 'capture.configure' | 'capture.validate' ? { config: CaptureConfig } : M extends 'capture.upload' | 'capture.delete' ? { digest: string } : M extends 'capture.read' ? { digest: string; offset: number } : EmptyParams }

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
  return (value.mode === undefined || ['unconfigured', 'managed', 'independent'].includes(value.mode as string)) &&
    (value.managed_available === undefined || typeof value.managed_available === 'boolean') && (value.independent_available === undefined || typeof value.independent_available === 'boolean') &&
    (value.host_name === undefined || nullableString(value.host_name, 512)) &&
    (value.server_origin === undefined || nullableString(value.server_origin, 4096)) &&
    (value.profile === undefined || validProfile(value.profile)) &&
    (value.config === undefined || value.config === null || validConfigMetadata(value.config)) &&
    (value.error === undefined || (isRecord(value.error) && boundedString(value.error.code, 128) && boundedString(value.error.message, 2048)))
}

function validManagement(value: unknown): boolean {
  return isRecord(value) && ['auto_connect', 'auto_reconnect', 'telemetry_enabled', 'manual_disconnect', 'desired_connected', 'worker_running'].every(key => typeof value[key] === 'boolean') &&
    (value.kill_switch_enabled === undefined || typeof value.kill_switch_enabled === 'boolean') &&
    (value.kill_switch === undefined || (isRecord(value.kill_switch) && ['available', 'enabled', 'tun_allowed', 'persistent'].every(key => typeof (value.kill_switch as Record<string, unknown>)[key] === 'boolean') && safeCount(value.kill_switch.filter_count) && typeof value.kill_switch.error_code === 'string' && value.kill_switch.error_code.length <= 128)) &&
    ['retry_attempt', 'retry_in_seconds', 'last_sync_at', 'last_report_at'].every(key => safeCount(value[key])) &&
    safeCount(value.sync_interval_seconds) && value.sync_interval_seconds >= 15 && value.sync_interval_seconds <= 3600 &&
    nullableString(value.last_error, 256) && nullableString(value.last_error_code, 64)
}
function validGroupId(value: unknown): value is string { return typeof value === 'string' && /^custom-[a-z0-9-]{1,41}$/.test(value) }
function boundedStrings(value: unknown, count: number, bytes: number): value is string[] {
  return Array.isArray(value) && value.length <= count && value.every(item => boundedString(item, bytes) && !/[\u0000-\u001f\u007f]/.test(item) && new TextEncoder().encode(item).length <= bytes)
}
function validProbeUrl(value: unknown): boolean {
  if (!boundedString(value, 4096) || /[\u0000-\u0020\u007f]/.test(value)) return false
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password } catch { return false }
}
export function validPreferencesEnvelope(value: unknown): value is PreferencesEnvelope {
  const base64 = (text: unknown, min: number, max: number) => {
    if (typeof text !== 'string' || text.length > 900 * 1024 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) return false
    try { const bytes = atob(text); return bytes.length >= min && bytes.length <= max && btoa(bytes) === text } catch { return false }
  }
  return isRecord(value) && Object.keys(value).length === 7 && value.format === 'sb-easy.preferences' && value.version === 1 && value.kdf === 'pbkdf2-sha256' && value.iterations === 600000 && base64(value.salt, 16, 16) && base64(value.nonce, 12, 12) && base64(value.ciphertext, 17, 640 * 1024 + 16)
}
function validArchivePassword(value: unknown): value is string { return typeof value === 'string' && !value.includes('\0') && new TextEncoder().encode(value).length >= 12 && new TextEncoder().encode(value).length <= 1024 }
function validSession(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) }
function validUpdateStatus(value: unknown): value is UpdateStatus {
  if (!isRecord(value) || !['supported', 'installed_service', 'publisher_configured', 'busy', 'cancellable'].every(key => typeof value[key] === 'boolean') ||
    !boundedString(value.current_version, 32) || !boundedString(value.current_core_version, 32) || !safeCount(value.received_bytes) || value.received_bytes > 536870912 ||
    !['unavailable', 'idle', 'checking', 'available', 'current', 'deferred', 'downloading', 'ready', 'installing', 'succeeded', 'rolled_back', 'failed', 'cancelled', 'recovery_required'].includes(value.phase as string)) return false
  const release = value.release
  if (release !== undefined && (!isRecord(release) || !validSession(release.id) || !boundedString(release.version, 31) || !boundedString(release.core_version, 31) ||
    release.channel !== 'stable' || !safeCount(release.bytes) || release.bytes < 1 || release.bytes > 536870912 || !safeCount(release.rollout_percent) || release.rollout_percent > 100)) return false
  const result = value.last_result
  return (value.error === undefined || (isRecord(value.error) && boundedString(value.error.code, 64) && boundedString(value.error.message, 256))) &&
    (result === undefined || (isRecord(result) && ['installing', 'succeeded', 'rolled_back', 'failed', 'recovery_required'].includes(result.phase as string) &&
      boundedString(result.version, 31) && safeCount(result.installer_code) && typeof result.reboot_required === 'boolean' && typeof result.state_restored === 'boolean' && typeof result.error_code === 'string' && result.error_code.length <= 64))
}
function validCloud(value: unknown): value is PreferencesCloud {
  return isRecord(value) && ['connected', 'mfa_required', 'revision_known'].every(key => typeof value[key] === 'boolean') &&
    typeof value.server === 'string' && value.server.length <= 8192 && typeof value.username === 'string' && value.username.length <= 256 &&
    (value.session_id === '' || validSession(value.session_id)) && safeCount(value.revision) && (value.updated_at === undefined || safeCount(value.updated_at)) &&
    (value.deleted === undefined || typeof value.deleted === 'boolean') && (value.envelope === undefined || value.envelope === null || validPreferencesEnvelope(value.envelope))
}
function validHealthPolicy(value: unknown): value is HealthPolicy {
  if (!isRecord(value) || Object.keys(value).length !== 6 || typeof value.enabled !== 'boolean' || !boundedString(value.probe_url, 2048) || !validProbeUrl(value.probe_url) || !value.probe_url.startsWith('https://') || /[#\\]/.test(value.probe_url) || value.probe_url.slice(8).split(/[/?]/)[0]?.includes('@')) return false
  return safeCount(value.interval_seconds) && value.interval_seconds >= 30 && value.interval_seconds <= 86400 &&
    safeCount(value.timeout_millis) && value.timeout_millis >= 500 && value.timeout_millis <= 30000 &&
    safeCount(value.tolerance_millis) && value.tolerance_millis <= 10000 && ['failover', 'fastest'].includes(value.selection as string)
}
function validHealthSnapshot(value: unknown): value is HealthSnapshot {
  return isRecord(value) && typeof value.running === 'boolean' && typeof value.checking === 'boolean' &&
    ['checked_at', 'completed', 'total'].every(key => safeCount(value[key])) && typeof value.error_code === 'string' && value.error_code.length <= 128 &&
    Array.isArray(value.results) && value.results.length <= 256 && value.results.every(r => isRecord(r) && boundedString(r.tag, 512) && typeof r.success === 'boolean' && (r.delay_ms === null || (safeCount(r.delay_ms) && r.delay_ms <= 30000)) && typeof r.error_code === 'string' && r.error_code.length <= 128) &&
    Array.isArray(value.groups) && value.groups.length <= 64 && value.groups.every(g => isRecord(g) && boundedString(g.id, 64) && typeof g.selected === 'string' && g.selected.length <= 512 && typeof g.automatic === 'boolean' && typeof g.error_code === 'string' && g.error_code.length <= 128)
}
function optionalProbeTimeout(value: unknown, max: number): boolean { return value === undefined || (safeCount(value) && value >= 1000 && value <= max) }
function validSubscriptionSource(value: unknown): boolean {
  if (!isRecord(value) || !boundedString(value.id, 128) || !boundedString(value.name, 1024) || !Array.isArray(value.tags) || value.tags.length > 1024 || !value.tags.every(tag => boundedString(tag, 512))) return false
  if (!['node_count', 'refresh_interval_minutes', 'last_attempt_at', 'last_success_at', 'next_refresh_at'].every(key => value[key] === undefined || safeCount(value[key])) ||
    (value.remote !== undefined && typeof value.remote !== 'boolean') || (value.last_error !== undefined && !nullableString(value.last_error, 128))) return false
  const m = value.metadata
  if (m !== undefined && (!isRecord(m) || typeof m.available !== 'boolean' || typeof m.header_present !== 'boolean' ||
    !['upload_bytes', 'download_bytes', 'total_bytes', 'used_bytes', 'remaining_bytes', 'expires_at'].every(key => m[key] === undefined || safeCount(m[key])) ||
    !['expired', 'quota_exhausted'].every(key => m[key] === undefined || typeof m[key] === 'boolean') || (m.warning !== undefined && !nullableString(m.warning, 128)))) return false
  const report = value.report
  return report === undefined || (isRecord(report) && (Object.keys(report).length === 0 ||
    (safeCount(report.imported) && safeCount(report.skipped) && ['sing-box-json', 'clash-yaml', 'uri'].includes(report.format as string) && typeof report.base64 === 'boolean' &&
    Array.isArray(report.warnings) && report.warnings.length <= 256 && report.warnings.every(w => isRecord(w) && safeCount(w.position) && boundedString(w.reason, 128)))))
}

export function validParams<M extends Method>(method: M, value: unknown): value is ParamsMap[M] {
  if (!isRecord(value)) return false
  if (method === 'updates.check') {
    if (Object.keys(value).length !== 1 || !boundedString(value.manifest_url, 4096) || !value.manifest_url.startsWith('https://') || /[?#\\\s]/.test(value.manifest_url) || value.manifest_url.slice(8).split('/')[0]?.includes('@')) return false
    try { const url = new URL(value.manifest_url); return !!url.hostname && url.pathname !== '/' && !value.manifest_url.split('/').some(part => part === '.' || part === '..') } catch { return false }
  }
  if (method === 'updates.download' || method === 'updates.install') return Object.keys(value).length === 1 && validSession(value.release_id)
  if (method === 'updates.status' || method === 'updates.cancel' || method === 'updates.recover') return Object.keys(value).length === 0
  if (method === 'preferences.export') return Object.keys(value).length === 1 && validArchivePassword(value.password)
  if (method === 'preferences.preview') return Object.keys(value).length === 2 && validArchivePassword(value.password) && validPreferencesEnvelope(value.envelope)
  if (method === 'preferences.apply') return Object.keys(value).length === 1 && validSession(value.preview_id)
  if (method === 'preferences.cloud.login') return Object.keys(value).length === 3 && validProbeUrl(value.server) && (value.server as string).startsWith('https://') && boundedString(value.username, 256) && boundedString(value.password, 4096)
  if (method === 'preferences.cloud.mfa') return Object.keys(value).length === 2 && validSession(value.session_id) && boundedString(value.code, 128) && !/[\u0000-\u0020\u007f]/.test(value.code)
  if (method === 'preferences.cloud.get' || method === 'preferences.cloud.logout') return Object.keys(value).length === 1 && validSession(value.session_id)
  if (method === 'preferences.cloud.delete') return Object.keys(value).length === 2 && validSession(value.session_id) && safeCount(value.revision)
  if (method === 'preferences.cloud.put') return Object.keys(value).length === 3 && validSession(value.session_id) && safeCount(value.revision) && validArchivePassword(value.password)
  if (method === 'routing.health.set') return validHealthPolicy(value)
  if (method === 'routing.automatic.set') return Object.keys(value).length === 2 && typeof value.group === 'string' && /^[a-z0-9-]{1,64}$/.test(value.group) && boundedStrings(value.candidates, 32, 512) && value.candidates.length > 0 && new Set(value.candidates).size === value.candidates.length
  if (method === 'mode.set') return Object.keys(value).length === 1 && ['managed', 'independent'].includes(value.mode as string)
  if (method === 'subscriptions.refresh') return Object.keys(value).length === 1 && boundedString(value.id, 36)
  if (method === 'subscriptions.import') return Object.keys(value).every(key => ['name', 'body', 'url', 'id', 'refresh_interval_minutes'].includes(key)) && boundedString(value.name, 100) &&
    (value.id === undefined || boundedString(value.id, 36)) && (value.refresh_interval_minutes === undefined || (safeCount(value.refresh_interval_minutes) && (value.refresh_interval_minutes === 0 || value.refresh_interval_minutes >= 15) && value.refresh_interval_minutes <= 10080)) &&
    ((boundedString(value.body, 262144) && value.url === undefined) || (boundedString(value.url, 8192) && value.body === undefined))
  if (method === 'management.settings.set') return Object.keys(value).length > 0 && Object.entries(value).every(([key, item]) =>
    key === 'sync_interval_seconds' ? safeCount(item) && item >= 15 && item <= 3600 : ['auto_connect', 'auto_reconnect', 'telemetry_enabled', 'kill_switch_enabled'].includes(key) && typeof item === 'boolean')
  if (method === 'routing.group_remove') return Object.keys(value).length === 1 && validGroupId(value.id)
  if (method === 'routing.group_save') return Object.keys(value).every(key => ['id', 'label', 'domains', 'processes', 'mode', 'node'].includes(key)) &&
    Object.keys(value).length === (value.mode === 'node' ? 6 : 5) && validGroupId(value.id) && boundedString(value.label, 128) &&
    boundedStrings(value.domains, 256, 253) && boundedStrings(value.processes, 64, 260) && value.domains.length + value.processes.length > 0 &&
    (value.mode === 'default' || (value.mode === 'node' && boundedString(value.node, 512)))
  if (method === 'routing.probe') return Object.keys(value).every(key => ['url', 'timeout_ms'].includes(key)) && validProbeUrl(value.url) && optionalProbeTimeout(value.timeout_ms, 15000)
  if (method === 'routing.delay') return Object.keys(value).every(key => ['target', 'url', 'timeout_ms'].includes(key)) && boundedString(value.target, 512) &&
    (value.url === undefined || validProbeUrl(value.url)) && optionalProbeTimeout(value.timeout_ms, 10000)
  if (method === 'subscriptions.fetch') return Object.keys(value).length === 1 && (boundedString(value.url, 8192) || boundedString(value.id, 36))
  if (method === 'subscriptions.remove') return Object.keys(value).length === 1 && boundedString(value.id, 36)
  if (method === 'subscriptions.save') return Object.keys(value).every(key => ['id','name','url','nodes'].includes(key)) && boundedString(value.name, 100) && (value.id === undefined || boundedString(value.id, 36)) && (value.url === undefined ? boundedString(value.id,36) : boundedString(value.url,8192)) && Array.isArray(value.nodes) && value.nodes.length > 0 && value.nodes.length <= 256 && value.nodes.every(isRecord)
  if (method === 'httpdebug.attach') return Object.keys(value).length === 1 && Array.isArray(value.domains) && value.domains.length > 0 && value.domains.length <= 64 && value.domains.every(d => typeof d === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$/.test(d))
  if (['httpdebug.start','httpdebug.stop','httpdebug.snapshot','httpdebug.certificate','httpdebug.open','httpdebug.export','httpdebug.trust','httpdebug.untrust'].includes(method)) return Object.keys(value).length === 0
  if (method === 'extensions.catalog_update') return Object.keys(value).length === 1 && boundedString(value.envelope, 900 * 1024) && new TextEncoder().encode(value.envelope as string).length <= 900 * 1024
  if (method === 'extensions.install' || method === 'extensions.rollback') return Object.keys(value).length === 1 && isExtensionId(value.id)
  if (method === 'extensions.change') return Object.keys(value).length === 2 && isExtensionId(value.id) && ['enable','disable','remove'].includes(value.action as string)
  if (method === 'routing.set') return typeof value.group === 'string' && /^[a-z0-9-]{1,64}$/.test(value.group) &&
    (value.mode === 'node' ? Object.keys(value).length === 3 && boundedString(value.node, 512) && !/[\u0000-\u001f\u007f]/.test(value.node) && new TextEncoder().encode(value.node).length <= 512 :
      Object.keys(value).length === 2 && (value.mode === 'server' || (value.mode === 'default' && value.group !== 'default')))
  if (method === 'capture.configure' || method === 'capture.validate') return Object.keys(value).length === 1 && validCaptureConfig(value.config)
  if (method === 'capture.upload' || method === 'capture.delete' || method === 'capture.read') return typeof value.digest === 'string' && /^[a-f0-9]{64}$/.test(value.digest) && (method === 'capture.read' ? Object.keys(value).length === 2 && safeCount(value.offset) && value.offset <= 786432 : Object.keys(value).length === 1)
  if (method === 'routing.gpt_node') return Object.keys(value).length === 1 && boundedString(value.outbound, 512) && !/[\u0000-\u001f\u007f]/.test(value.outbound) && new TextEncoder().encode(value.outbound).length <= 512
  if (method === 'enrollment.apply') return Object.keys(value).length === 1 && boundedString(value.uri, 16_384)
  if (!['routing.health.check', 'management.settings.get', 'extensions.catalog', 'extensions.progress', 'extensions.list', 'service.start', 'protocol.hello', 'enrollment.status', 'enrollment.forget', 'status.get', 'config.summary', 'config.refresh', 'config.validate', 'routing.gpt_default', 'routing.gpt_server', 'connection.start', 'connection.stop', 'config.inspect', 'runtime.snapshot', 'traffic.snapshot', 'traffic.clear', 'logs.snapshot', 'capture.snapshot', 'capture.rotate'].includes(method)) return false
  return Object.keys(value).length === 0
}

function validExtensionTrust(value: Record<string, unknown>): boolean {
  return ['verified', 'revoked', 'update_available', 'rollback_available', 'pending_health', 'catalog_fresh', 'install_available'].every(k => value[k] === undefined || typeof value[k] === 'boolean') && (value.build === undefined || (Number.isSafeInteger(value.build) && (value.build as number) >= 0))
}

export function validResult<M extends Method>(method: M, value: unknown): value is ResultMap[M] {
  if (!isRecord(value)) return false
  switch (method) {
    case 'updates.status': case 'updates.check': case 'updates.download': case 'updates.install': case 'updates.cancel': case 'updates.recover': return validUpdateStatus(value)
    case 'preferences.export': return validPreferencesEnvelope(value.envelope)
    case 'preferences.preview': return validSession(value.preview_id) && safeCount(value.expires_in_seconds) && value.expires_in_seconds <= 300 && boundedStrings(value.subscription_names, 16, 100) && safeCount(value.node_count) && value.node_count <= 4096 && safeCount(value.routing_count) && value.routing_count <= 64 && value.device_settings_preserved === true
    case 'preferences.cloud.login': case 'preferences.cloud.mfa': case 'preferences.cloud.logout': case 'preferences.cloud.get': case 'preferences.cloud.put': case 'preferences.cloud.delete': return validCloud(value)
    case 'management.settings.get': case 'management.settings.set': return validManagement(value)
    case 'routing.delay': return boundedString(value.target, 512) && boundedString(value.url, 4096) && safeCount(value.delay_ms) && value.delay_ms <= 60000 && typeof value.success === 'boolean'
    case 'routing.probe': return boundedString(value.url, 4096) && boundedString(value.host, 253) && safeCount(value.port) && value.port <= 65535 &&
      typeof value.success === 'boolean' && safeCount(value.http_status) && value.http_status <= 599 && safeCount(value.elapsed_ms) && typeof value.error_code === 'string' && value.error_code.length <= 64 &&
      isRecord(value.evidence) && typeof value.evidence.observed === 'boolean' && ['dns', 'public_exit_ip', 'process_scope'].every(key => typeof (value.evidence as Record<string, unknown>)[key] === 'string') &&
      Array.isArray(value.evidence.logs) && value.evidence.logs.length <= 200 && value.evidence.logs.every(line => typeof line === 'string' && line.length <= 4096) &&
      (value.evidence.connection === undefined || (isRecord(value.evidence.connection) && boundedString(value.evidence.connection.id, 2048) &&
        typeof value.evidence.connection.rule === 'string' && isRecord(value.evidence.connection.metadata) && Object.values(value.evidence.connection.metadata).every(item => typeof item === 'string' && item.length <= 2048) &&
        boundedStrings(value.evidence.connection.chains, 32, 2048)))
    case 'httpdebug.start': case 'httpdebug.stop': case 'httpdebug.snapshot': case 'httpdebug.attach': return ['starting','running','stopped','failed'].includes(value.phase as string) && typeof value.error === 'string' && typeof value.url === 'string' && typeof value.attached === 'boolean'
    case 'httpdebug.certificate': return typeof value.der === 'string' && value.der.length < 32768 && /^[0-9a-f]+$/.test(value.der)
    case 'httpdebug.export': case 'httpdebug.open': case 'httpdebug.trust': case 'httpdebug.untrust': return value.ready === true
    case 'extensions.catalog_update':
    case 'extensions.catalog': return validExtensionTrust(value) && (value.trust_configured === undefined || typeof value.trust_configured === 'boolean') && (value.sequence === undefined || (Number.isSafeInteger(value.sequence) && (value.sequence as number) >= 0)) && Array.isArray(value.items) && value.items.length <= 16 && value.items.every(e => isRecord(e) && isExtensionId(e.id) && boundedString(e.name,128) && boundedString(e.version,32) && boundedString(e.publisher,128) && boundedString(e.description,512) && boundedString(e.permissions,512) && validExtensionTrust(e) && (e.installed_version === undefined || (typeof e.installed_version === 'string' && e.installed_version.length <= 32)) && (e.available_build === undefined || (Number.isSafeInteger(e.available_build) && (e.available_build as number) > 0)) && Number.isSafeInteger(e.size) && (e.size as number) > 0 && (e.size as number) <= 167772160)
    case 'extensions.install':
    case 'extensions.progress': return (isExtensionId(value.id) || (value.phase === 'idle' && value.id === '')) && ['idle','downloading','verifying','ready','installing','complete','failed'].includes(value.phase as string) && Number.isSafeInteger(value.received) && (value.received as number) >= 0 && Number.isSafeInteger(value.total) && (value.total as number) >= (value.phase === 'idle' ? 0 : 1) && (value.received as number) <= (value.total as number) + 1 && typeof value.error === 'string' && value.error.length <= 64
    case 'extensions.list':
    case 'extensions.rollback':
    case 'extensions.change': return Array.isArray(value.extensions) && value.extensions.length <= 16 && value.extensions.every(e => isRecord(e) && isExtensionId(e.id) && boundedString(e.name,128) && typeof e.version === 'string' && e.version.length <= 32 && validExtensionTrust(e) && ['installed','enabled','running','failed'].every(k => typeof e[k] === 'boolean'))
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
    case 'mode.set':
    case 'connection.start':
    case 'connection.stop':
      return boundedString(value.phase, 64) && typeof value.enrolled === 'boolean' &&
        typeof value.core_running === 'boolean' && typeof value.connection_available === 'boolean' && validDeviceMetadata(value) &&
        (value.management === undefined || validManagement(value.management)) &&
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
    case 'subscriptions.import':
    case 'subscriptions.refresh':
    case 'subscriptions.remove':
    case 'preferences.apply':
    case 'routing.health.set':
    case 'routing.health.check':
    case 'routing.automatic.set':
    case 'routing.set':
    case 'routing.group_save':
    case 'routing.group_remove':
    case 'config.validate':
      return (value.health_policy === undefined || validHealthPolicy(value.health_policy)) && (value.health === undefined || validHealthSnapshot(value.health)) &&
        (value.subscriptions === undefined || (isRecord(value.subscriptions) && typeof value.subscriptions.sources_available === 'boolean' && ['managed','local'].every(key => { const list = (value.subscriptions as Record<string, unknown>)[key]; return Array.isArray(list) && list.length <= 1024 && list.every(validSubscriptionSource) }))) && (value.routing_live === undefined || typeof value.routing_live === 'boolean') &&
        (value.routing_groups === undefined || (Array.isArray(value.routing_groups) && value.routing_groups.length <= 64 && value.routing_groups.every(g => isRecord(g) &&
          boundedString(g.id,64) && boundedString(g.label,512) && nullableString(g.server_outbound,512) && nullableString(g.outbound,512) &&
          ['server','default','node','automatic'].includes(g.mode as string) && (g.mode !== 'automatic' || (boundedStrings(g.automatic_candidates, 32, 512) && g.automatic_candidates.length > 0)) && typeof g.editable === 'boolean' && typeof g.reason === 'string' && (g.local === undefined || typeof g.local === 'boolean') && (g.domains === undefined || boundedStrings(g.domains, 256, 253)) && (g.processes === undefined || boundedStrings(g.processes, 64, 260))))) &&
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
