import type { ConfigMetadata, StatusResult } from './protocol.js'

export function connectionActions(status: StatusResult | null, config: ConfigMetadata | null) {
  const running = status?.core_running === true || status?.phase === 'RUNNING'
  const changed = Boolean(config?.candidate_available && config.downloaded_etag && config.downloaded_etag !== config.active_etag)
  return {
    startLabel: running ? '应用新配置' : '启动连接',
    canStart: status?.enrolled === true && status.connection_available && config?.candidate_available === true &&
      ['STOPPED', 'DEGRADED', 'RUNNING'].includes(status.phase) && (!running || changed),
    canStop: Boolean(status && (status.core_running || ['RUNNING', 'DEGRADED'].includes(status.phase))),
    canForget: status?.phase === 'STOPPED' && !status.core_running,
  }
}

export function runtimeDetail(status: StatusResult): string {
  if (status.phase === 'STARTING') return '正在校验并启动候选配置，等待本地内核健康检查完成。'
  if (status.phase === 'ROLLING_BACK') return '新配置未能正常启动，服务正在恢复上一次可用配置。'
  if (status.phase === 'STOPPING') return '正在停止内核并清理本机连接。'
  if (status.core_running) {
    if (status.tun_active === true) return '本地内核健康检查已通过，TUN 已启用。尚未验证互联网连通性。'
    if (status.tun_active === false) return '本地内核健康检查已通过；当前配置未启用 TUN。尚未验证互联网连通性。'
    return '本机服务报告内核运行中，TUN 状态尚未提供。尚未验证互联网连通性。'
  }
  if (status.phase === 'DEGRADED') return '内核未正常运行。可查看错误后重新启动，或断开并清理残余连接。'
  if (!status.connection_available) return '设备已注册。需要可用的本机内核和候选配置才能启动；下载和校验不会自动建立连接。'
  return '本地内核未运行。启动会校验并应用已下载的候选配置；含 TUN 的配置可能改变本机网络。'
}
