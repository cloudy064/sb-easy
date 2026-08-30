export interface Telemetry {
  available?: boolean
  up?: number
  down?: number
  up_total?: number
  down_total?: number
  conn_count?: number
}

export interface AgentStatus {
  running?: boolean | null
  version?: string
  server?: string
  etag?: string | null
  last_cycle?: string | null
  last_error?: string | null
  rule_source?: string
  pending?: Record<string, boolean>
  telemetry?: Telemetry
}

export interface ProxyHistory {
  delay?: number
  time?: string
}

export interface ClashProxy {
  type?: string
  now?: string
  all?: string[]
  history?: ProxyHistory[]
}

export interface ProxyPayload {
  proxies?: Record<string, ClashProxy>
  error?: string
}

export interface AgentSettings {
  local_proxy_egress?: boolean
  default_proxy_outbound?: string | null
  outbound_server_overrides?: Record<string, string>
  outbound_overrides?: Record<string, unknown>
}
