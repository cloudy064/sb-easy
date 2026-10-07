import type { ConfigMetadata, ConfigValidation, StatusResult } from './protocol.js'

// Validation belongs to the exact downloaded candidate; it never implies a
// running core or an active VPN, including after a same-version download.
export function configStage(summary: (ConfigMetadata & { validation?: ConfigValidation }) | null, runtime?: StatusResult | null) {
  if (!summary) return {
    state: 'unknown', canValidate: false, label: '配置状态尚未读取',
    detail: '请先读取完整的配置摘要，以确认下载和校验状态。',
  }
  const validation = summary?.validation
  const matches = Boolean(summary?.candidate_available && summary.downloaded_etag &&
    validation?.checked_etag === summary.downloaded_etag)
  const state = validation?.state === 'valid' || validation?.state === 'invalid'
    ? matches ? validation.state : 'not_checked'
    : validation?.state ?? 'unknown'
  const canValidate = summary?.candidate_available === true && state !== 'unavailable' && state !== 'unknown'
  const active = Boolean(summary.active_etag)
  const same = active && summary.active_etag === summary.downloaded_etag
  const running = runtime?.core_running === true
  const suffix = active
    ? same ? '此配置已激活；运行状态以本机服务为准。' : '当前仍使用先前激活的配置；下载和校验不会自动切换。'
    : running ? '本地内核运行中，其激活版本尚未确认。'
      : runtime && ['STARTING', 'ROLLING_BACK', 'STOPPING', 'DEGRADED'].includes(runtime.phase)
        ? '本地连接正在处理或需要恢复，请以最新运行状态为准。' : '此配置尚未激活，VPN 未启动。'
  if (!summary?.candidate_available) return {
    state, canValidate: false, label: '尚未下载配置',
    detail: `先从服务器下载候选配置，再使用本机 sing-box 内核校验。${suffix}`,
  }
  switch (state) {
    case 'valid': return { state, canValidate, label: same ? running ? '当前配置 · 运行中' : '已激活 · 运行待确认' : active ? '新候选已校验 · 待应用' : '已校验 · 未激活', detail: `当前候选配置已通过 sing-box check。${suffix}` }
    case 'invalid': return { state, canValidate, label: active && !same ? '新候选校验失败 · 旧配置保留' : '校验未通过', detail: `当前候选配置未通过内核校验。${suffix}` }
    case 'unavailable': return { state, canValidate, label: '已下载 · 内核不可用', detail: `本机尚未提供可用的 sing-box 内核，暂时无法校验。${suffix}` }
    case 'not_checked': return { state, canValidate, label: active && !same ? '新候选待校验 · 旧配置保留' : '已下载 · 待内核校验', detail: `候选配置已保存，尚未通过本机 sing-box 校验。${suffix}` }
    default: return { state, canValidate, label: '已下载 · 校验状态未知', detail: `服务尚未提供候选配置的校验状态。${suffix}` }
  }
}
