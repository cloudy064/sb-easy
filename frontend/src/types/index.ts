export interface WireGuardPeer {
  id: string
  name: string
  public_key: string
  address: string
  enabled: boolean
  persistent_keepalive: number
  allowed_ips: string
  expire_at: string | null
  quota_bytes?: number
  created_at: string
  updated_at: string
  notes: string | null
  dns: string
  endpoint?: string
  latest_handshake?: number
  transfer_rx?: number
  transfer_tx?: number
  expired?: boolean
}

export interface ProxyNode {
  id: string
  tag: string
  node_type: 'shadowsocks' | 'vmess' | 'trojan' | 'vless' | 'hysteria2' | 'tuic'
  enabled: boolean
  server: string
  server_port: number
  protocol_config: string
  subscription_id: string | null
  fingerprint: string
  latency: number | null
  last_latency_test: string | null
  created_at: string
  updated_at: string
}

export interface Subscription {
  id: string
  name: string
  url: string
  enabled: boolean
  refresh_interval: number
  last_fetched_at: string | null
  last_fetch_result: string | null
  created_at: string
  updated_at: string
}

export interface FetchResult {
  added: number
  updated: number
  skipped: number
  errors: string[]
}

export interface ProxyGroup {
  name: string
  type: string
  now: string
  all: string[]
  selectable: boolean
}

export interface Connection {
  id: string
  upload: number
  download: number
  start: string
  chains: string[]
  rule: string
  metadata: {
    network: string
    host: string
    destinationIP: string
    destinationPort: string
  }
}

export interface LogLine {
  type: string
  payload: string
}

export interface NodeFormConfig {
  method?: string
  password?: string
  uuid?: string
  flow?: string
  security?: string
  alter_id?: number
  packet_encoding?: string
  congestion_control?: string
  tls?: Record<string, unknown>
  transport?: Record<string, unknown>
  [key: string]: unknown
}
