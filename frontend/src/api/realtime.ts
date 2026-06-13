// Helper for the sing-box streaming WebSocket endpoints proxied by the backend.
// Auth rides in the query string (?token=<jwt>) because browsers can't set an
// Authorization header on a WebSocket handshake.

export type Stream = 'traffic' | 'logs' | 'connections' | 'memory'

export function openStream(
  kind: Stream,
  onMessage: (data: any) => void,
  opts: { level?: string; host?: string } = {},
): WebSocket | null {
  const token = localStorage.getItem('sb-easy-token')
  if (!token) return null

  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const params = new URLSearchParams({ token })
  if (kind === 'logs' && opts.level) params.set('level', opts.level)
  // Select which managed host's sing-box to stream from (over WG); omit for local.
  if (opts.host && opts.host !== 'self') params.set('host', opts.host)
  const url = `${proto}://${location.host}/api/sing-box/ws/${kind}?${params.toString()}`

  const ws = new WebSocket(url)
  ws.onmessage = (ev) => {
    try {
      onMessage(JSON.parse(ev.data))
    } catch {
      onMessage(ev.data)
    }
  }
  return ws
}

export function formatBytes(b: number): string {
  const n = Number(b)
  if (!Number.isFinite(n) || n <= 0) return '0 B'
  if (n < 1024) return Math.round(n) + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB'
  return (n / 1073741824).toFixed(2) + ' GB'
}

export function formatRate(bytesPerSec: number): string {
  return formatBytes(bytesPerSec) + '/s'
}
