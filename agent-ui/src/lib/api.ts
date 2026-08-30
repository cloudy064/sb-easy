export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message)
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body) headers.set('Content-Type', 'application/json')
  if (init.method && init.method !== 'GET' && init.method !== 'HEAD') {
    headers.set('X-SB-Easy-UI', '1')
  }
  const response = await fetch(path, { ...init, cache: 'no-store', headers })
  const raw = await response.text()
  let body: unknown = {}
  try {
    body = raw ? JSON.parse(raw) : {}
  } catch {
    body = { error: raw }
  }
  if (!response.ok) {
    const message =
      typeof body === 'object' && body && 'error' in body
        ? String((body as { error: unknown }).error)
        : `HTTP ${response.status}`
    throw new ApiError(message, response.status)
  }
  return body as T
}
