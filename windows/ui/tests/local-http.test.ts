import assert from 'node:assert/strict'
import { test } from 'node:test'
import { BridgeError, HttpTransport, NativeBridge, readLocalSession, type LocalSessionScope } from '../src/lib/bridge.js'

const token = 'a'.repeat(64)
const status = { phase: 'UNENROLLED', enrolled: false, core_running: false, connection_available: false }
const codeIs = (code: string) => (error: unknown) => error instanceof BridgeError && error.code === code
function scope(hash = '', saved?: string) {
  const values = new Map<string, string>(saved ? [['sb-easy-local-session', saved]] : [])
  let replacement: string | URL | null | undefined
  const browser: LocalSessionScope = {
    location: { protocol: 'http:', hostname: '127.0.0.1', port: '49001', hash, pathname: '/', search: '', origin: 'http://127.0.0.1:49001' },
    history: { state: null, replaceState: (_data, _unused, url) => { replacement = url } },
    sessionStorage: { getItem: key => values.get(key) ?? null, setItem: (key, value) => { values.set(key, value) }, removeItem: key => { values.delete(key) } },
  }
  return { browser, values, replacement: () => replacement }
}

test('local capability is removed from the URL and retained for tab reload only', () => {
  const page = scope(`#session=${token}`)
  assert.equal(readLocalSession(page.browser), token)
  assert.equal(page.replacement(), '/')
  page.browser.location.hash = ''
  assert.equal(readLocalSession(page.browser), token)
  assert.equal(readLocalSession(scope().browser), undefined)
})

test('missing, malformed and non-loopback capabilities cannot activate HTTP transport', () => {
  const invalid = scope('#session=bad', token)
  assert.equal(readLocalSession(invalid.browser), undefined)
  assert.equal(invalid.values.size, 0)
  for (const patch of [{ hostname: 'example.test' }, { hostname: '127.0.0.1.example.test' }, { protocol: 'https:' }, { port: '' }]) {
    const page = scope(`#session=${token}`)
    Object.assign(page.browser.location, patch)
    assert.equal(readLocalSession(page.browser), undefined)
  }
  const denied = scope(`#session=${token}`)
  denied.browser.sessionStorage.setItem = () => { throw new Error('Storage blocked') }
  assert.equal(readLocalSession(denied.browser), token)
  const bridge = new NativeBridge(undefined)
  return assert.rejects(bridge.request('status.get'), /从托盘打开网页/)
})

test('HTTP RPC sends its capability only in the same-origin authorization header', async () => {
  const fetcher: typeof fetch = async (url, options) => {
    assert.equal(url, '/api/rpc')
    assert.equal(options?.method, 'POST')
    assert.equal(options?.mode, 'same-origin')
    assert.equal(options?.credentials, 'omit')
    assert.equal(options?.redirect, 'error')
    assert.deepEqual(options?.headers, { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' })
    assert.ok(!String(options?.body).includes(token))
    const request = JSON.parse(String(options?.body))
    assert.deepEqual({ version: request.version, method: request.method, params: request.params }, { version: 1, method: 'status.get', params: {} })
    return Response.json({ version: 1, id: request.id, ok: true, result: status })
  }
  const bridge = new NativeBridge(new HttpTransport(token, fetcher))
  assert.deepEqual(await bridge.request('status.get'), status)
  bridge.dispose()
})

test('HTTP failures, expired sessions, malformed JSON and mismatched envelopes reject', async () => {
  const cases: Array<[() => Promise<Response>, string]> = [
    [async () => new Response('', { status: 401 }), 'session_expired'],
    [async () => new Response('', { status: 403 }), 'session_expired'],
    [async () => new Response('', { status: 500 }), 'http_error'],
    [async () => new Response('<html>'), 'invalid_response'],
    [async () => new Response('bad', { headers: { 'Content-Type': 'application/json' } }), 'invalid_response'],
    [async () => Response.json({ id: 'other', ok: true, result: status }), 'invalid_response'],
    [async () => { throw new TypeError('network failure') }, 'service_unavailable'],
  ]
  for (const [fetcher, code] of cases) {
    const bridge = new NativeBridge(new HttpTransport(token, fetcher))
    await assert.rejects(bridge.request('status.get'), codeIs(code))
    bridge.dispose()
  }
})

test('HTTP preserves service errors and aborts requests when their deadline expires', async () => {
  const rejected = new NativeBridge(new HttpTransport(token, async (_url, options) => Response.json({
    id: JSON.parse(String(options?.body)).id, version: 1, ok: false, error: { code: 'NO_CONFIG', message: 'No configuration' },
  })))
  await assert.rejects(rejected.request('connection.start'), codeIs('NO_CONFIG'))
  rejected.dispose()
  let signal: AbortSignal | null | undefined
  const waiting = new NativeBridge(new HttpTransport(token, async (_url, options) => {
    signal = options?.signal
    return await new Promise<Response>(() => {})
  }), 5)
  await assert.rejects(waiting.request('status.get'), codeIs('timeout'))
  assert.equal(signal?.aborted, true)
  waiting.dispose()
})
