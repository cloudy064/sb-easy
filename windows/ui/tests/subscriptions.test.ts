import assert from 'node:assert/strict'
import { test } from 'node:test'
import { parseSubscription } from '../src/lib/subscriptions.js'
test('Clash nodes convert without importing routes or DNS', () => {
  const nodes = parseSubscription('proxies:\n  - {name: US, type: trojan, server: example.invalid, port: 443, password: secret, sni: tls.invalid}\nrules: [MATCH,DIRECT]')
  assert.equal(nodes[0].type, 'trojan')
  assert.deepEqual(nodes[0].tls, { enabled: true, server_name: 'tls.invalid' })
  assert.equal('rules' in nodes[0], false)
})
test('base64 URI lists retain Unicode names and credential separators', () => {
  const link = 'ss://' + Buffer.from('aes-128-gcm:p:a:ss').toString('base64') + '@example.invalid:8388#%E6%97%A5%E6%9C%AC'
  const nodes = parseSubscription(Buffer.from(link).toString('base64'))
  assert.equal(nodes[0].tag, '日本'); assert.equal(nodes[0].password, 'p:a:ss')
})
test('sing-box imports only nodes; duplicate names and external references reject atomically', () => {
  const n = { tag: 'same', type: 'http', server: 'example.invalid', server_port: 80 }
  assert.equal(parseSubscription(JSON.stringify({ outbounds: [n, { type: 'selector', tag: 'group' }] })).length, 1)
  assert.throws(() => parseSubscription(JSON.stringify([n, n])), /第 2/)
  assert.throws(() => parseSubscription(JSON.stringify([{ ...n, detour: 'managed-node' }])), /第 1/)
  assert.throws(() => parseSubscription('proxies:\n - {name: invalid, type: unknown, password: PRIVATE_PASSWORD}'), e => e instanceof Error && !e.message.includes('PRIVATE_PASSWORD'))
})
test('VLESS Reality and websocket preserve TLS and transport', () => {
  const n = parseSubscription('vless://uuid@example.invalid:443?security=reality&pbk=public&sid=abcd&type=ws&path=%2Fpath#Node')[0]
  assert.deepEqual(n.transport, { type: 'ws', path: '/path' })
  assert.deepEqual((n.tls as Record<string, unknown>).reality, { enabled: true, public_key: 'public', short_id: 'abcd' })
})
