import assert from 'node:assert/strict'
import { test } from 'node:test'
import { previewEnrollment } from '../src/lib/enrollment.js'

const code = 'abcdef0123456789'.repeat(4)
const link = (server: string, registrationCode = code) => `sbeasy://enroll?server=${encodeURIComponent(server)}&code=${registrationCode}`

test('previews a canonical server base URL while keeping the code out of display data', () => {
  const preview = previewEnrollment(` ${link('https://Example.test/control/')} `)
  assert.deepEqual(preview, { serverOrigin: 'https://example.test/control', secure: true })
  assert.equal(JSON.stringify(preview).includes(code), false)
})

test('marks HTTP enrollment as unencrypted without rewriting the destination', () => {
  assert.deepEqual(previewEnrollment(link('http://127.0.0.1:51821/control')), {
    serverOrigin: 'http://127.0.0.1:51821/control', secure: false,
  })
})

test('rejects incomplete or ambiguous links without reflecting the supplied code', () => {
  for (const uri of [
    '', 'not a URL', link('https://example.test', 'short'),
    `${link('https://example.test')}&code=${code}`,
    `${link('https://example.test')}&server=https://other.test`,
    link('https://example.test').replace('sbeasy://', 'https://'),
    link('https://example.test').replace('enroll?', 'enroll/unexpected?'),
    `${link('https://example.test')}#fragment`,
  ]) {
    assert.throws(() => previewEnrollment(uri), (error: unknown) => {
      assert.ok(error instanceof Error)
      assert.equal(error.message.includes(code), false)
      return true
    })
  }
})

test('rejects credentials and non-HTTP destinations in the server URL', () => {
  for (const server of ['file:///secret', 'javascript:alert(1)', 'https://user:password@example.test',
    'https://example.test?token=secret', 'https://example.test#fragment']) {
    assert.throws(() => previewEnrollment(link(server)))
  }
})
