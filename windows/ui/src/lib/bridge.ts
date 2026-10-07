import { isRecord, validParams, validResult, type Method, type ParamsMap, type ResultMap } from './protocol.js'

export interface RequestOptions { timeoutMs?: number }

export interface HostMessage { data: unknown }

export interface WebViewTransport {
  postMessage(message: unknown): void
  addEventListener(type: 'message', listener: (event: HostMessage) => void): void
  removeEventListener(type: 'message', listener: (event: HostMessage) => void): void
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
  method: Method
  resolve(value: unknown): void
  reject(error: BridgeError): void
  timer: ReturnType<typeof setTimeout>
}

// No HTTP fallback: a browser preview must never impersonate the Windows service.
export function findNativeTransport(scope: unknown = globalThis): WebViewTransport | undefined {
  if (!isRecord(scope) || !isRecord(scope.chrome) || !isRecord(scope.chrome.webview)) return undefined
  const candidate = scope.chrome.webview
  if (typeof candidate.postMessage !== 'function' || typeof candidate.addEventListener !== 'function' ||
      typeof candidate.removeEventListener !== 'function') return undefined
  return candidate as unknown as WebViewTransport
}

export class NativeBridge {
  readonly available: boolean
  private readonly transport?: WebViewTransport
  private readonly timeoutMs: number
  private readonly pending = new Map<string, PendingRequest>()
  private readonly prefix = Math.random().toString(36).slice(2)
  private sequence = 0
  private disposed = false

  constructor(transport: WebViewTransport | undefined, timeoutMs = 5000) {
    this.transport = transport
    this.available = Boolean(transport)
    this.timeoutMs = timeoutMs
    transport?.addEventListener('message', this.onMessage)
  }

  request<M extends Exclude<Method, 'enrollment.apply'>>(method: M, params?: ParamsMap[M], options?: RequestOptions): Promise<ResultMap[M]>
  request(method: 'enrollment.apply', params: ParamsMap['enrollment.apply'], options?: RequestOptions): Promise<ResultMap['enrollment.apply']>
  request<M extends Method>(method: M, params: ParamsMap[M] = {} as ParamsMap[M], options: RequestOptions = {}): Promise<ResultMap[M]> {
    if (this.disposed) return Promise.reject(new BridgeError('bridge_closed', '原生通信已关闭'))
    if (!this.transport) return Promise.reject(new BridgeError('host_unavailable', '原生宿主不可用'))
    if (!validParams(method, params)) return Promise.reject(new BridgeError('invalid_params', '请求参数格式无效'))
    const timeoutMs = options.timeoutMs ?? this.timeoutMs
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 45_000) {
      return Promise.reject(new BridgeError('invalid_timeout', '请求等待时间无效'))
    }
    if (this.pending.size >= 32) return Promise.reject(new BridgeError('too_many_requests', '待处理请求过多'))
    const id = `${this.prefix}-${++this.sequence}`
    return new Promise<ResultMap[M]>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new BridgeError('timeout', '服务响应超时；操作结果尚未确认，请先刷新状态'))
      }, timeoutMs)
      this.pending.set(id, { method, resolve: value => resolve(value as ResultMap[M]), reject, timer })
      try {
        this.transport!.postMessage({ id, version: 1, method, params })
      } catch {
        this.finish(id, new BridgeError('send_failed', '无法向原生宿主发送请求'))
      }
    })
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.transport?.removeEventListener('message', this.onMessage)
    for (const id of this.pending.keys()) this.finish(id, new BridgeError('bridge_closed', '原生通信已关闭'))
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
      this.pending.delete(data.id)
      pending.resolve(data.result)
    } else if (data.ok === false && isRecord(data.error) && typeof data.error.code === 'string' &&
        data.error.code.length > 0 && data.error.code.length <= 128 &&
        typeof data.error.message === 'string' && data.error.message.length > 0 && data.error.message.length <= 2048) {
      this.finish(data.id, new BridgeError(data.error.code, data.error.message))
    } else {
      this.finish(data.id, new BridgeError('invalid_response', '服务返回的数据格式无效'))
    }
  }

  private finish(id: string, error: BridgeError): void {
    const pending = this.pending.get(id)
    if (!pending) return
    clearTimeout(pending.timer)
    this.pending.delete(id)
    pending.reject(error)
  }
}
