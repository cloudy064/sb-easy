import assert from 'node:assert/strict'
import { test } from 'node:test'
import { validExtensionRequest, validFrameMessage } from '../src/lib/extensions.js'

test('plugin messages require the exact opaque frame source and per-frame channel', () => {
  const frame = {} as Window, other = {} as Window, channel = 'a'.repeat(32)
  const event = { origin: 'null', source: frame, data: { channel } }
  assert.equal(validFrameMessage(event, frame, channel), true)
  assert.equal(validFrameMessage({ ...event, source: other }, frame, channel), false)
  assert.equal(validFrameMessage({ ...event, origin: 'http://127.0.0.1:1234' }, frame, channel), false)
  assert.equal(validFrameMessage({ ...event, data: { channel: 'other' } }, frame, channel), false)
  assert.equal(validFrameMessage(event, null, channel), false)
})

test('plugin RPC allowlists do not expose enrollment, preferences or unrelated plugins', () => {
  const request = { id: 'extension-1', method: 'traffic.snapshot', params: {} }
  assert.equal(validExtensionRequest('statistics', request), true)
  assert.equal(validExtensionRequest('capture', request), false)
  for (const method of ['enrollment.status', 'enrollment.apply', 'preferences.export', 'connection.start', 'httpdebug.trust']) {
    assert.equal(validExtensionRequest('statistics', { ...request, method }), false)
  }
  assert.equal(validExtensionRequest('http-debug', { ...request, method: 'httpdebug.trust' }), true)
  assert.equal(validExtensionRequest('http-debug', { ...request, method: 'httpdebug.trust', params: { der: 'injected' } }), false)
  assert.equal(validExtensionRequest('statistics', { ...request, timeoutMs: 45001 }), false)
  assert.equal(validExtensionRequest('statistics', { ...request, params: { extra: true } }), false)
})
