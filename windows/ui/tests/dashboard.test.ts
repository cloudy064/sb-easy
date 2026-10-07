import test from 'node:test'
import assert from 'node:assert/strict'
import { bytes, rates } from '../src/lib/dashboard.js'
import { validParams, validResult, type RuntimeSnapshot } from '../src/lib/protocol.js'

const snapshot: RuntimeSnapshot = { running: true, core_pid: 123, sample_ms: 1000, etag: 'revision-1', upload_total: 1024, download_total: 2048, connection_count: 0, connections: [], nodes: [] }
test('runtime snapshots accept real counters and reject malformed connections or invented fields', () => {
  assert.equal(validResult('runtime.snapshot', snapshot), true)
  assert.equal(validResult('runtime.snapshot', { ...snapshot, upload_total: -1 }), false)
  assert.equal(validResult('runtime.snapshot', { ...snapshot, connections: [{ host: 'missing required fields' }] }), false)
  assert.equal(validResult('runtime.snapshot', { ...snapshot, core_pid: '123' }), false)
  assert.equal(validParams('runtime.snapshot', { path: '/arbitrary-endpoint' }), false)
})
test('config inspection keeps candidate and active versions distinct', () => {
  const catalog = { etag: 'revision-1', final: 'Tokyo', node_count: 1, rule_count: 0, nodes: [{ tag: 'Tokyo', type: 'trojan', selected: '', members: [], member_count: 0 }], inbounds: [], rules: [] }
  assert.equal(validResult('config.inspect', { active: null, candidate: catalog }), true)
  assert.equal(validResult('config.inspect', { active: catalog, candidate: { ...catalog, etag: 'revision-2' } }), true)
  assert.equal(validResult('config.inspect', { active: null, candidate: { ...catalog, nodes: [{ ...catalog.nodes[0], members: ['bad\0tag'] }] } }), false)
})
test('rates use actual sample times and require two measurements', () => {
  assert.equal(rates(null, snapshot), null)
  assert.deepEqual(rates(snapshot, { ...snapshot, sample_ms: 3000, upload_total: 2048, download_total: 4096 }), { up: 512, down: 1024 })
})
test('restarts, changed configs, counter reset and long pauses never produce misleading rates', () => {
  for (const changed of [{ core_pid: 456 }, { etag: 'revision-2' }, { upload_total: 0 }, { sample_ms: 15000 }, { running: false }]) {
    assert.equal(rates(snapshot, { ...snapshot, sample_ms: 3000, ...changed }), null)
  }
})
test('unknown traffic renders an em dash instead of fabricated zero', () => {
  assert.equal(bytes(null), '—'); assert.equal(bytes(undefined), '—'); assert.equal(bytes(0), '0 B'); assert.equal(bytes(1024), '1.0 KB')
})
