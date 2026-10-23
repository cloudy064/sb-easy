import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { decryptArchive, encryptArchive, validateEnvelope } from '../src/lib/secureArchive.ts'
const vector = JSON.parse(await readFile(new URL('../../testdata/preferences-v1.json', import.meta.url), 'utf8'))
test('UTF-8 interoperability vector and randomized archive round trip', async () => {
  assert.deepEqual(await decryptArchive(vector.envelope, vector.passphrase), vector.payload)
  const first = await encryptArchive(vector.payload, vector.passphrase)
  const second = await encryptArchive(vector.payload, vector.passphrase)
  assert.notEqual(first.salt, second.salt); assert.notEqual(first.nonce, second.nonce)
  assert.deepEqual(await decryptArchive(first, vector.passphrase), vector.payload)
})
test('wrong key, bit tampering, cross-purpose and malformed metadata fail closed', async () => {
  await assert.rejects(decryptArchive(vector.envelope, 'a different passphrase'), /Incorrect passphrase/)
  const bytes = Buffer.from(vector.envelope.ciphertext, 'base64'); bytes[4] ^= 1
  await assert.rejects(decryptArchive({ ...vector.envelope, ciphertext: bytes.toString('base64') }, vector.passphrase), /damaged/)
  await assert.rejects(decryptArchive({ ...vector.envelope, format: 'sb-easy.backup' }, vector.passphrase, 'backup'), /damaged/)
  for (const change of [{ iterations: 1 }, { version: 2 }, { salt: 'AA==' }, { plaintext: 'secret' }, { kdf: 'plain' }]) assert.throws(() => validateEnvelope({ ...vector.envelope, ...change }, 'preferences'))
  await assert.rejects(encryptArchive({}, 'short'), /passphrase/)
  await assert.rejects(encryptArchive({ data: 'x'.repeat(1024 * 1024) }, vector.passphrase), /exceeds/)
})
