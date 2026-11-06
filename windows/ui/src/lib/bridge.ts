import { isRecord, validParams, validResult, type Method, type ParamsMap, type ResultMap } from './protocol.js'

export interface RequestOptions { timeoutMs?: number }

export interface HostMessage { data: unknown }

export interface RpcTransport {
  postMessage(message: unknown): void
  addEventListener(type: 'message', listener: (event: HostMessage) => void): void
  removeEventListener(type: 'message', listener: (event: HostMessage) => void): void
  cancel?(id: string): void
}

export class BridgeError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'BridgeError'
    this.code = code
  }
}

interface PendingRequest {
  params: unknown
  attempts: number
  retryTimer?: ReturnType<typeof setTimeout>
  method: Method
  resolve(value: unknown): void
  reject(error: BridgeError): void
  timer: ReturnType<typeof setTimeout>
}

const retryableReads = new Set<Method>([
  'httpdebug.snapshot', 'runtime.snapshot', 'traffic.snapshot', 'capture.snapshot', 'capture.read',
  'extensions.list', 'extensions.catalog', 'extensions.progress',
  'management.settings.get', 'status.get', 'config.summary', 'config.inspect', 'logs.snapshot',
])

const sessionKey = 'sb-easy-local-session'
export interface LocalSessionScope {
  location: Pick<Location, 'protocol' | 'hostname' | 'port' | 'hash' | 'pathname' | 'search' | 'origin'>
  history: Pick<History, 'replaceState' | 'state'>
  sessionStorage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>
}

export function readLocalSession(scope: LocalSessionScope): string | undefined {
  const { location } = scope
  if (location.protocol !== 'http:' || location.hostname !== '127.0.0.1' || !/^\d+$/.test(location.port)) return undefined
  const supplied = location.hash.startsWith('#session=')
  const token = supplied ? /^#session=([a-f0-9]{64})$/i.exec(location.hash)?.[1] : undefined
  if (supplied) {
    // Remove the capability before any RPC, diagnostics or external navigation.
    scope.history.replaceState(scope.history.state, '', location.pathname + location.search)
    try {
      if (token) scope.sessionStorage.setItem(sessionKey, token)
      else scope.sessionStorage.removeItem(sessionKey)
    } catch { /* The first page remains usable when storage is disabled. */ }
    return token
  }
  try {
    const saved = scope.sessionStorage.getItem(sessionKey)
    return saved && /^[a-f0-9]{64}$/i.test(saved) ? saved : undefined
  } catch { return undefined }
}

export class HttpTransport implements RpcTransport {
  private readonly listeners = new Set<(event: HostMessage) => void>()
  private readonly active = new Map<string, AbortController>()

  constructor(private readonly token: string, private readonly fetcher: typeof fetch = globalThis.fetch.bind(globalThis)) {}

  postMessage(message: unknown): void {
    if (!isRecord(message) || typeof message.id !== 'string') throw new Error('Invalid RPC envelope')
    const id = message.id, controller = new AbortController()
    this.active.set(id, controller)
    void this.send(message, controller).then(data => {
      if (!controller.signal.aborted) for (const listener of this.listeners) listener({ data })
    }).catch(error => {
      if (!controller.signal.aborted) for (const listener of this.listeners) listener({ data: {
        version: 1, id, ok: false,
        error: error instanceof BridgeError ? { code: error.code, message: error.message }
          : { code: 'service_unavailable', message: '无法连接本机服务，请从托盘重新打开网页' },
      } })
    }).finally(() => { if (this.active.get(id) === controller) this.active.delete(id) })
  }

  private async send(message: Record<string, unknown>, controller: AbortController): Promise<unknown> {
    const response = await this.fetcher('/api/rpc', {
      method: 'POST', mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store',
      headers: { Authorization: `Bearer ${this.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(message), signal: controller.signal,
    })
    if (response.status === 401 || response.status === 403) throw new BridgeError('session_expired', '本机管理会话已失效，请从托盘重新打开网页')
    if (!response.ok) throw new BridgeError('http_error', `本机服务请求失败（HTTP ${response.status}），请刷新状态后重试`)
    if (!response.headers.get('Content-Type')?.toLowerCase().includes('application/json')) throw new BridgeError('invalid_response', '本机服务返回的数据格式无效')
    let data: unknown
    try { data = await response.json() } catch { throw new BridgeError('invalid_response', '本机服务返回的数据格式无效') }
    if (!isRecord(data) || data.id !== message.id) throw new BridgeError('invalid_response', '本机服务响应与请求不匹配')
    return data
  }

  addEventListener(_type: 'message', listener: (event: HostMessage) => void): void { this.listeners.add(listener) }
  removeEventListener(_type: 'message', listener: (event: HostMessage) => void): void { this.listeners.delete(listener) }
  cancel(id: string): void { this.active.get(id)?.abort(); this.active.delete(id) }
}

export function findLocalTransport(): RpcTransport | undefined {
  if (typeof window === 'undefined') return undefined
  const token = readLocalSession(window)
  return token ? new HttpTransport(token) : undefined
}

export class NativeBridge {
  readonly available: boolean
  private readonly transport?: RpcTransport
  private readonly timeoutMs: number
  private readonly pending = new Map<string, PendingRequest>()
  private readonly prefix = Math.random().toString(36).slice(2)
  private sequence = 0
  private disposed = false

  constructor(transport: RpcTransport | undefined, timeoutMs = 5000) {
    this.transport = transport
    this.available = Boolean(transport)
    this.timeoutMs = timeoutMs
    transport?.addEventListener('message', this.onMessage)
  }

  request<M extends Exclude<Method, 'enrollment.apply'>>(method: M, params?: ParamsMap[M], options?: RequestOptions): Promise<ResultMap[M]>
  request(method: 'enrollment.apply', params: ParamsMap['enrollment.apply'], options?: RequestOptions): Promise<ResultMap['enrollment.apply']>
  request<M extends Method>(method: M, params: ParamsMap[M] = {} as ParamsMap[M], options: RequestOptions = {}): Promise<ResultMap[M]> {
    if (this.disposed) return Promise.reject(new BridgeError('bridge_closed', '本机服务通信已关闭'))
    if (!this.transport) return Promise.reject(new BridgeError('host_unavailable', '请从托盘打开网页以连接本机服务'))
    if (!validParams(method, params)) return Promise.reject(new BridgeError('invalid_params', '请求参数格式无效'))
    const timeoutMs = options.timeoutMs ?? this.timeoutMs
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > (method === 'service.start' ? 300_000 : method === 'connection.start' || method === 'updates.install' ? 95_000 : 45_000)) {
      return Promise.reject(new BridgeError('invalid_timeout', '请求等待时间无效'))
    }
    if (this.pending.size >= 32) return Promise.reject(new BridgeError('too_many_requests', '待处理请求过多'))
    const id = `${this.prefix}-${++this.sequence}`
    return new Promise<ResultMap[M]>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.finish(id, new BridgeError('timeout', retryableReads.has(method)
          ? '服务持续忙碌或响应超时，请稍后刷新'
          : '服务响应超时；操作结果尚未确认，请先刷新状态'))
      }, timeoutMs)
      this.pending.set(id, { method, params, attempts: 0, resolve: value => resolve(value as ResultMap[M]), reject, timer })
      try {
        this.transport!.postMessage({ id, version: 1, method, params })
      } catch {
        this.finish(id, new BridgeError('send_failed', '无法向本机服务发送请求'))
      }
    })
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.transport?.removeEventListener('message', this.onMessage)
    for (const id of this.pending.keys()) this.finish(id, new BridgeError('bridge_closed', '本机服务通信已关闭'))
  }

  private readonly onMessage = (event: HostMessage): void => {
    const data = event.data
    if (!isRecord(data) || typeof data.id !== 'string' || data.id.length > 128) return
    const pending = this.pending.get(data.id)
    if (!pending) return
    if (data.version !== undefined && data.version !== 1) {
      this.finish(data.id, new BridgeError('protocol_mismatch', '服务通信版本不兼容'))
      return
    }
    if (data.ok === true && validResult(pending.method, data.result)) {
      clearTimeout(pending.timer)
      clearTimeout(pending.retryTimer)
      this.pending.delete(data.id)
      pending.resolve(data.result)
    } else if (data.ok === false && isRecord(data.error) && typeof data.error.code === 'string' &&
        data.error.code.length > 0 && data.error.code.length <= 128 &&
        typeof data.error.message === 'string' && data.error.message.length > 0 && data.error.message.length <= 2048) {
      if (data.error.code === 'BUSY' && retryableReads.has(pending.method)) {
        // Only retry reads, without extending the original deadline or replaying mutations.
        if (pending.retryTimer !== undefined) return
        const id = data.id
        pending.retryTimer = setTimeout(() => {
          pending.retryTimer = undefined
          if (!this.pending.has(id)) return
          try {
            this.transport!.postMessage({ id, version: 1, method: pending.method, params: pending.params })
          } catch {
            this.finish(id, new BridgeError('send_failed', '无法向本机服务发送请求'))
          }
        }, Math.min(100 * 2 ** pending.attempts++, 800) + Math.floor(Math.random() * 75))
        return
      }
      this.finish(data.id, new BridgeError(data.error.code, data.error.message))
    } else {
      this.finish(data.id, new BridgeError('invalid_response', '服务返回的数据格式无效'))
    }
  }

  private finish(id: string, error: BridgeError): void {
    const pending = this.pending.get(id)
    if (!pending) return
    clearTimeout(pending.timer)
    clearTimeout(pending.retryTimer)
    this.pending.delete(id)
    this.transport?.cancel?.(id)
    pending.reject(error)
  }
}
