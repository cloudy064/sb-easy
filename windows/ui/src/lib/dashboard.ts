import type { RuntimeSnapshot } from './protocol.js'

export function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let index = 0
  while (value >= 1024 && index < units.length - 1) { value /= 1024; ++index }
  return `${value.toFixed(index === 0 ? 0 : value >= 100 ? 0 : 1)} ${units[index]}`
}
export function rates(previous: RuntimeSnapshot | null, current: RuntimeSnapshot): { up: number; down: number } | null {
  if (!previous?.running || !current.running || previous.core_pid !== current.core_pid || previous.etag !== current.etag) return null
  const interval = (current.sample_ms - previous.sample_ms) / 1000
  if (interval <= 0 || interval > 10 || current.upload_total < previous.upload_total || current.download_total < previous.download_total) return null
  return { up: (current.upload_total - previous.upload_total) / interval, down: (current.download_total - previous.download_total) / interval }
}
export function shortVersion(value: string | null | undefined): string { return value ? value.replace(/^"|"$/g, '').slice(0, 14) : '—' }
export function nodeKind(value: string): string {
  const key = value.toLowerCase()
  return ({ selector: '手动代理组', urltest: '自动测速组', direct: '直接连接', block: '阻止连接' } as Record<string, string>)[key] ?? value
}
export function graphPoints(values: number[], max: number): string {
  return values.map((value, index) => `${(index / 29 * 600).toFixed(1)},${(110 - Math.max(0, value) / Math.max(max, 1) * 90).toFixed(1)}`).join(' ')
}
