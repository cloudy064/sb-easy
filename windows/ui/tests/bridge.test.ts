import assert from 'node:assert/strict'
import { test } from 'node:test'
import { BridgeError, findNativeTransport, NativeBridge, type HostMessage, type WebViewTransport } from '../src/lib/bridge.js'
import { validParams, validResult } from '../src/lib/protocol.js'
import { configStage } from '../src/lib/config.js'
import { connectionActions, runtimeDetail } from '../src/lib/connection.js'

class TestTransport implements WebViewTransport {
  messages: Array<{ id: string; version: number; method: string; params: object }> = []
  listeners = new Set<(event: HostMessage) => void>()
  failSend = false

  postMessage(message: unknown): void {
    if (this.failSend) throw new Error('host disconnected')
    this.messages.push(message as typeof this.messages[number])
  }

  addEventListener(_type: 'message', listener: (event: HostMessage) => void): void {
    this.listeners.add(listener)
  }

  removeEventListener(_type: 'message', listener: (event: HostMessage) => void): void {
    this.listeners.delete(listener)
  }

  respond(data: unknown): void {
    for (const listener of this.listeners) listener({ data })
  }
}

const hello = { protocol_version: 1, service_version: '0.1.0', supported_methods: ['protocol.hello', 'status.get', 'enrollment.status'] }
const status = { phase: 'UNENROLLED', enrolled: false, core_running: false, connection_available: false }
const codeIs = (code: string) => (error: unknown) => error instanceof BridgeError && error.code === code

test('browser preview has no native fallback or fabricated service response', async () => {
  assert.equal(findNativeTransport({}), undefined)
  assert.equal(findNativeTransport({ chrome: { webview: { postMessage: true } } }), undefined)
  const bridge = new NativeBridge(undefined)
  assert.equal(bridge.available, false)
  await assert.rejects(bridge.request('protocol.hello'), codeIs('host_unavailable'))
  bridge.dispose()
})

test('requests use protocol v1 and correlate out-of-order responses', async () => {
  const transport = new TestTransport()
  assert.equal(findNativeTransport({ chrome: { webview: transport } }), transport)
  const bridge = new NativeBridge(transport)
  const first = bridge.request('protocol.hello')
  const second = bridge.request('status.get')
  assert.deepEqual(transport.messages.map(({ version, method, params }) => ({ version, method, params })), [
    { version: 1, method: 'protocol.hello', params: {} },
    { version: 1, method: 'status.get', params: {} },
  ])
  assert.notEqual(transport.messages[0].id, transport.messages[1].id)
  assert.ok(transport.messages.every(message => message.id.length > 0 && message.id.length <= 128))
  transport.respond({ id: transport.messages[1].id, version: 1, ok: true, result: status })
  transport.respond({ id: transport.messages[0].id, version: 1, ok: true, result: hello })
  assert.deepEqual(await first, hello)
  assert.deepEqual(await second, status)
  bridge.dispose()
})

test('ignores unrelated notifications and accepts response without optional version', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  const pending = bridge.request('enrollment.status')
  transport.respond(null)
  transport.respond('invalid json')
  transport.respond({ id: 'different-request', ok: true, result: status })
  transport.respond({ id: transport.messages[0].id, ok: true, result: { enrolled: false, phase: 'UNENROLLED', future_field: 'allowed' } })
  assert.equal((await pending).enrolled, false)
  bridge.dispose()
})

test('propagates service error without claiming a successful connection', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  const pending = bridge.request('status.get')
  const rejected = assert.rejects(pending, codeIs('service_unavailable'))
  transport.respond({ id: transport.messages[0].id, ok: false, error: { code: 'service_unavailable', message: 'Service is not running' } })
  await rejected
  bridge.dispose()
})

test('rejects incompatible envelope and malformed result fields', async () => {
  for (const response of [
    { version: 2, ok: true, result: status },
    { version: 1, ok: true, result: { ...status, core_running: 'false' } },
    { ok: true, result: {} },
    { ok: false, error: { code: 'error', message: {} } },
    { ok: 'true', result: status },
  ]) {
    const transport = new TestTransport()
    const bridge = new NativeBridge(transport)
    const pending = bridge.request('status.get')
    const rejected = assert.rejects(pending, codeIs(response.version === 2 ? 'protocol_mismatch' : 'invalid_response'))
    transport.respond({ id: transport.messages[0].id, ...response })
    await rejected
    bridge.dispose()
  }
})

test('rejects unsupported hello version and absent capability list', async () => {
  for (const result of [{ ...hello, protocol_version: 2 }, { protocol_version: 1, service_version: '0.1' }]) {
    const transport = new TestTransport()
    const bridge = new NativeBridge(transport)
    const rejected = assert.rejects(bridge.request('protocol.hello'), codeIs('invalid_response'))
    transport.respond({ id: transport.messages[0].id, ok: true, result })
    await rejected
    bridge.dispose()
  }
})

test('times out a request and ignores its late reply', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport, 10)
  await assert.rejects(bridge.request('status.get'), codeIs('timeout'))
  transport.respond({ id: transport.messages[0].id, ok: true, result: status })
  const pending = bridge.request('status.get')
  transport.respond({ id: transport.messages[1].id, ok: true, result: status })
  assert.deepEqual(await pending, status)
  bridge.dispose()
})

test('send failure rejects immediately; disposal rejects pending requests and removes listener', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  transport.failSend = true
  await assert.rejects(bridge.request('status.get'), codeIs('send_failed'))
  transport.failSend = false
  const rejected = assert.rejects(bridge.request('status.get'), codeIs('bridge_closed'))
  bridge.dispose()
  await rejected
  assert.equal(transport.listeners.size, 0)
  await assert.rejects(bridge.request('status.get'), codeIs('bridge_closed'))
  bridge.dispose()
})

test('bounds outstanding native requests', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  const pending = Array.from({ length: 32 }, () => assert.rejects(bridge.request('status.get'), codeIs('bridge_closed')))
  await assert.rejects(bridge.request('status.get'), codeIs('too_many_requests'))
  assert.equal(transport.messages.length, 32)
  bridge.dispose()
  await Promise.all(pending)
})

const profile = { id: 'profile-1', name: 'Managed profile' }
const candidate = {
  candidate_available: true, downloaded_etag: 'config-v2', active_etag: null,
  rule_source: 'quickjs', profile, counts: { inbounds: 1, outbounds: 5, rules: 12 },
}
const enrolled = {
  enrolled: true, phase: 'STOPPED', host_name: 'Test device', server_origin: 'https://example.test/control', profile,
  config: { candidate_available: false, downloaded_etag: null, active_etag: null, rule_source: null },
}

test('enrollment transmits explicit URI once and supports a longer per-request deadline', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport, 1)
  const uri = `sbeasy://enroll?server=https%3A%2F%2Fexample.test&code=${'a'.repeat(64)}`
  const pending = bridge.request('enrollment.apply', { uri }, { timeoutMs: 45_000 })
  await new Promise(resolve => setTimeout(resolve, 8))
  assert.equal(transport.messages.length, 1)
  assert.deepEqual(transport.messages[0].params, { uri })
  transport.respond({ id: transport.messages[0].id, ok: true, result: enrolled })
  assert.equal((await pending).server_origin, 'https://example.test/control')
  bridge.dispose()
})

test('enrollment timeout does not retry a one-time code', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  await assert.rejects(bridge.request('enrollment.apply', { uri: 'sbeasy://enroll?test' }, { timeoutMs: 5 }), codeIs('timeout'))
  await new Promise(resolve => setTimeout(resolve, 8))
  assert.equal(transport.messages.length, 1)
  bridge.dispose()
})

test('request parameters are constrained by method and timeout is bounded', async () => {
  assert.equal(validParams('enrollment.apply', {}), false)
  assert.equal(validParams('enrollment.apply', { uri: 42 }), false)
  assert.equal(validParams('enrollment.apply', { uri: 'x', token: 'secret' }), false)
  assert.equal(validParams('enrollment.apply', { uri: 'x'.repeat(16_385) }), false)
  assert.equal(validParams('config.refresh', { force: true }), false)
  assert.equal(validParams('config.validate', {}), true)
  assert.equal(validParams('config.validate', { activate: true }), false)
  assert.equal(validParams('connection.start', {}), true)
  assert.equal(validParams('connection.stop', {}), true)
  assert.equal(validParams('connection.start', { uri: 'https://example.test' }), false)
  assert.equal(validParams('connection.stop', { force: true }), false)
  assert.equal(validParams('enrollment.forget', {}), true)
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  await assert.rejects(bridge.request('enrollment.apply', { uri: '' }), codeIs('invalid_params'))
  await assert.rejects(bridge.request('status.get', {}, { timeoutMs: 45_001 }), codeIs('invalid_timeout'))
  assert.equal(transport.messages.length, 0)
  bridge.dispose()
})

test('config download returns candidate metadata without marking it active', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  const pending = bridge.request('config.refresh', {}, { timeoutMs: 45_000 })
  transport.respond({ id: transport.messages[0].id, version: 1, ok: true, result: candidate })
  const result = await pending
  assert.equal(result.candidate_available, true)
  assert.equal(result.active_etag, null)
  assert.equal(result.counts.rules, 12)
  assert.equal('config' in result, false)
  bridge.dispose()
})

test('accepts unregistered and registered metadata while rejecting malformed additions', () => {
  assert.equal(validResult('enrollment.apply', enrolled), true)
  assert.equal(validResult('enrollment.forget', { enrolled: false, phase: 'UNENROLLED', profile: null, server_origin: null }), true)
  assert.equal(validResult('status.get', { ...status, ...enrolled }), true)
  for (const extra of [
    { host_name: 4 }, { server_origin: {} }, { profile: { id: 'p', name: 8 } },
    { config: { candidate_available: 'true' } },
  ]) assert.equal(validResult('enrollment.status', { ...enrolled, ...extra }), false)
})

test('validates candidate counts, null ETags and metadata types', () => {
  assert.equal(validResult('config.summary', candidate), true)
  assert.equal(validResult('config.summary', {
    candidate_available: false, downloaded_etag: null, active_etag: null,
    rule_source: null, profile: null, counts: { inbounds: 0, outbounds: 0, rules: 0 },
  }), true)
  for (const result of [
    { ...candidate, counts: { inbounds: -1, outbounds: 5, rules: 12 } },
    { ...candidate, counts: { inbounds: 1, outbounds: 5, rules: '12' } },
    { ...candidate, counts: { inbounds: 1.5, outbounds: 5, rules: 12 } },
    { ...candidate, downloaded_etag: 3 }, { ...candidate, rule_source: {} },
    { ...candidate, profile: [] }, { ...candidate, candidate_available: 1 },
  ]) assert.equal(validResult('config.refresh', result), false)
})

test('preserves a storage failure in a successful status envelope instead of treating it as fresh enrollment', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  const pending = bridge.request('status.get')
  const failure = { code: 'STORAGE_CORRUPT', message: 'Stored device state is unavailable; it was left unchanged.' }
  transport.respond({ id: transport.messages[0].id, version: 1, ok: true, result: { ...status, phase: 'ERROR', error: failure } })
  const result = await pending
  assert.equal(result.phase, 'ERROR')
  assert.equal(result.enrolled, false)
  assert.deepEqual(result.error, failure)
  assert.equal(validResult('enrollment.status', { enrolled: false, phase: 'ERROR', error: failure }), true)
  assert.equal(validResult('status.get', { ...status, error: { code: 1, message: 'invalid' } }), false)
  assert.equal(validResult('status.get', { ...status, error: { code: 'error', message: {} } }), false)
  bridge.dispose()
})

test('validation accepts an exact candidate without activating a VPN', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  const pending = bridge.request('config.validate', {}, { timeoutMs: 45_000 })
  assert.deepEqual(transport.messages[0].params, {})
  assert.equal(transport.messages[0].method, 'config.validate')
  transport.respond({ id: transport.messages[0].id, version: 1, ok: true, result: {
    ...candidate, validation: { state: 'valid', checked_etag: candidate.downloaded_etag, core_version: '1.13.12' },
  } })
  const result = await pending
  assert.equal(result.active_etag, null)
  assert.equal('core_running' in result, false)
  assert.equal(configStage(result).label, '已校验 · 未激活')
  assert.match(configStage(result).detail, /VPN 未启动/)
  assert.equal(configStage({ ...result, downloaded_etag: 'a-new-candidate' }).state, 'not_checked')
  assert.equal(configStage({ ...result, downloaded_etag: null }).state, 'not_checked')
  assert.equal(configStage({ ...result, candidate_available: false }).canValidate, false)
  bridge.dispose()
})

test('validation state is optional for old services but malformed additions are rejected', () => {
  const validation = { state: 'not_checked', checked_etag: null, core_version: '1.13.12' }
  assert.equal(validResult('config.summary', candidate), true)
  assert.equal(configStage(candidate).state, 'unknown')
  assert.equal(configStage(candidate).canValidate, false)
  assert.equal(validResult('config.summary', { ...candidate, validation }), true)
  for (const invalid of [
    null, {}, { ...validation, state: 'running' }, { ...validation, state: ['valid'] },
    { ...validation, checked_etag: 4 }, { ...validation, core_version: '' },
    { ...validation, error: { code: 'CHECK_FAILED', message: {} } },
  ]) assert.equal(validResult('config.validate', { ...candidate, validation: invalid }), false)
  const unavailable = configStage({ ...candidate, validation: { ...validation, state: 'unavailable' } })
  assert.equal(unavailable.canValidate, false)
  assert.match(unavailable.detail, /内核/)
})

test('failed validation is not retried; refreshed summary retains the failure', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  const error = { code: 'CHECK_FAILED', message: 'Candidate configuration was rejected.' }
  const pending = assert.rejects(bridge.request('config.validate', {}, { timeoutMs: 45_000 }), codeIs('CHECK_FAILED'))
  transport.respond({ id: transport.messages[0].id, version: 1, ok: false, error })
  await pending
  assert.equal(transport.messages.length, 1)
  const summary = bridge.request('config.summary')
  transport.respond({ id: transport.messages[1].id, version: 1, ok: true, result: {
    ...candidate, validation: { state: 'invalid', checked_etag: candidate.downloaded_etag, core_version: '1.13.12', error },
  } })
  const result = await summary
  assert.equal(configStage(result).state, 'invalid')
  assert.equal(result.active_etag, null)
  assert.deepEqual(result.validation?.error, error)
  bridge.dispose()
})

test('start and stop use real status replies and never infer internet health', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  const running = { ...status, enrolled: true, phase: 'RUNNING', core_running: true, connection_available: true,
    tun_active: false, config: { ...candidate, active_etag: candidate.downloaded_etag, last_good_etag: candidate.downloaded_etag } }
  const start = bridge.request('connection.start', {}, { timeoutMs: 45_000 })
  assert.equal(transport.messages[0].method, 'connection.start')
  assert.deepEqual(transport.messages[0].params, {})
  transport.respond({ id: transport.messages[0].id, ok: true, result: running })
  const active = await start
  assert.equal(active.config?.active_etag, candidate.downloaded_etag)
  assert.match(runtimeDetail(active), /未启用 TUN/)
  assert.match(runtimeDetail(active), /尚未验证互联网连通性/)
  assert.match(runtimeDetail({ ...active, tun_active: true }), /TUN 已启用/)
  const stop = bridge.request('connection.stop', {}, { timeoutMs: 45_000 })
  transport.respond({ id: transport.messages[1].id, ok: true, result: {
    ...running, phase: 'STOPPED', core_running: false, tun_active: false, config: { ...running.config, active_etag: null },
  } })
  const stopped = await stop
  assert.equal(stopped.core_running, false)
  assert.equal(stopped.config?.active_etag, null)
  assert.equal(stopped.config?.last_good_etag, candidate.downloaded_etag)
  bridge.dispose()
})

test('optional connection fields support old services and reject malformed metadata', () => {
  assert.equal(validResult('status.get', status), true)
  for (const extra of [
    { tun_active: 'false' }, { runtime_error: { code: 3, message: 'failed' } },
    { runtime_error: { code: 'FAILED', message: [] } },
    { config: { ...candidate, last_good_etag: 17 } },
  ]) assert.equal(validResult('connection.start', { ...status, ...extra }), false)
  const rolledBack = { ...status, runtime_error: { code: 'ROLLED_BACK', message: 'Previous configuration restored.' } }
  assert.equal(validResult('status.get', rolledBack), true)
  assert.equal('error' in rolledBack, false)
  assert.equal(connectionActions(status, candidate).canStart, false)
})

test('connection controls require eligible phases and a different candidate while running', () => {
  const stopped = { ...status, enrolled: true, phase: 'STOPPED', connection_available: true }
  assert.equal(connectionActions(stopped, candidate).canStart, true)
  assert.equal(connectionActions(stopped, candidate).canForget, true)
  assert.equal(connectionActions(stopped, null).canStart, false)
  for (const phase of ['STARTING', 'ROLLING_BACK', 'STOPPING'])
    assert.equal(connectionActions({ ...stopped, phase }, candidate).canStart, false)
  const running = { ...stopped, phase: 'RUNNING', core_running: true }
  assert.equal(connectionActions(running, { ...candidate, active_etag: candidate.downloaded_etag }).canStart, false)
  assert.equal(connectionActions(running, { ...candidate, active_etag: 'previous-version' }).canStart, true)
  assert.equal(connectionActions(running, candidate).startLabel, '应用新配置')
  assert.equal(connectionActions(running, candidate).canStop, true)
  assert.equal(connectionActions(running, candidate).canForget, false)
  assert.equal(connectionActions({ ...stopped, phase: 'DEGRADED' }, candidate).canStart, true)
  assert.equal(connectionActions({ ...stopped, phase: 'DEGRADED', connection_available: false }, candidate).canStop, true)
})

test('new candidate failures and rollback do not erase the old running configuration', async () => {
  const running = { ...status, enrolled: true, phase: 'RUNNING', core_running: true, connection_available: true,
    config: { ...candidate, active_etag: 'previous-version', last_good_etag: 'previous-version' },
    runtime_error: { code: 'ROLLED_BACK', message: 'Previous configuration restored.' } }
  const pending = configStage({ ...running.config,
    validation: { state: 'not_checked', checked_etag: null, core_version: '1.13.12' },
  }, running)
  assert.match(pending.label, /新候选待校验/)
  assert.match(pending.detail, /当前仍使用先前激活的配置/)
  assert.doesNotMatch(pending.detail, /VPN 未启动/)
  const failed = configStage({ ...running.config,
    validation: { state: 'invalid', checked_etag: candidate.downloaded_etag, core_version: '1.13.12' },
  }, running)
  assert.match(failed.label, /新候选校验失败/)
  assert.doesNotMatch(failed.detail, /VPN 未启动/)
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  const rejected = assert.rejects(bridge.request('connection.start', {}, { timeoutMs: 45_000 }), codeIs('ROLLED_BACK'))
  transport.respond({ id: transport.messages[0].id, ok: false, error: running.runtime_error })
  await rejected
  assert.equal(transport.messages.length, 1)
  const refresh = bridge.request('status.get')
  transport.respond({ id: transport.messages[1].id, ok: true, result: running })
  const latest = await refresh
  assert.equal(latest.phase, 'RUNNING')
  assert.equal(latest.config?.active_etag, 'previous-version')
  assert.equal(latest.error, undefined)
  assert.equal(latest.runtime_error?.code, 'ROLLED_BACK')
  bridge.dispose()
})

test('timed out start does not automatically retry or claim activation', async () => {
  const transport = new TestTransport()
  const bridge = new NativeBridge(transport)
  await assert.rejects(bridge.request('connection.start', {}, { timeoutMs: 5 }), codeIs('timeout'))
  await new Promise(resolve => setTimeout(resolve, 8))
  assert.equal(transport.messages.length, 1)
  bridge.dispose()
})
