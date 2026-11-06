type Pending = {
  resolve: (value: unknown) => void
  reject: (reason: Error) => void
  timer: number
}

export type EnrollmentActivation = { server: string; code: string }

const pending = new Map<string, Pending>()
const activationListeners = new Set<(activation: EnrollmentActivation) => void>()
let nextId = 1

function nativeBridge() {
  const webview = window.chrome?.webview
  if (!webview) throw new Error('原生桥不可用，请从 sb-easy.exe 启动界面')
  return webview
}

nativeBridge().addEventListener('message', (event) => {
  const message = event.data
  if (!message || typeof message !== 'object') return
  if (message.type === 'rpc-result' && typeof message.id === 'string') {
    const item = pending.get(message.id)
    if (!item) return
    pending.delete(message.id)
    window.clearTimeout(item.timer)
    if (message.ok) item.resolve(message.result)
    else item.reject(new Error(typeof message.error === 'string' ? message.error : '操作失败'))
    return
  }
  if (
    message.type === 'enrollment-activation' &&
    typeof message.server === 'string' &&
    typeof message.code === 'string'
  ) {
    const activation = { server: message.server, code: message.code }
    activationListeners.forEach((listener) => listener(activation))
  }
})

export function rpc<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  const id = `ui-${Date.now()}-${nextId++}`
  return new Promise<T>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      pending.delete(id)
      reject(new Error('操作超时，请确认 sb-easy 服务正在运行'))
    }, 70_000)
    pending.set(id, {
      resolve: resolve as (value: unknown) => void,
      reject,
      timer,
    })
    try {
      nativeBridge().postMessage({ id, method, params })
    } catch (error) {
      window.clearTimeout(timer)
      pending.delete(id)
      reject(error instanceof Error ? error : new Error('无法发送原生请求'))
    }
  })
}

export function onEnrollmentActivation(listener: (activation: EnrollmentActivation) => void) {
  activationListeners.add(listener)
  return () => activationListeners.delete(listener)
}
