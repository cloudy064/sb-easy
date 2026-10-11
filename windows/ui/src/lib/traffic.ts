import { getDomain } from 'tldts'
import type { TrafficRow } from './protocol.js'

export function trafficDomain(host: string): string {
  const normalized = host.trim().toLowerCase().replace(/\.$/, '')
  return getDomain(normalized, { allowPrivateDomains: true }) ?? (normalized || '未知目标')
}
export interface TrafficGroup { key: string; upload: number; download: number; lastSeen: number; hosts: number; rows: TrafficRow[] }
export function groupTraffic(rows: TrafficRow[], by: 'app' | 'domain' | 'host' | 'outbound'): TrafficGroup[] {
  const groups = new Map<string, TrafficGroup>()
  for (const row of rows) {
    const key = by === 'app' ? row.app || '未知应用' : by === 'domain' ? trafficDomain(row.host) :
      by === 'host' ? row.host || '未知目标' : row.outbound || '未知出站'
    const group = groups.get(key) ?? { key, upload: 0, download: 0, lastSeen: 0, hosts: 0, rows: [] }
    group.upload += row.upload; group.download += row.download
    group.lastSeen = Math.max(group.lastSeen, row.last_seen); group.rows.push(row)
    groups.set(key, group)
  }
  return [...groups.values()].map(group => ({ ...group, hosts: new Set(group.rows.map(row => row.host)).size }))
}
