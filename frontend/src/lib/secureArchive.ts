export type ArchiveKind = 'preferences' | 'backup'
export interface SecureEnvelope {
  format: 'sb-easy.preferences' | 'sb-easy.backup'
  version: 1
  kdf: 'pbkdf2-sha256'
  iterations: 600000
  salt: string
  nonce: string
  ciphertext: string
}
export const ARCHIVE_LIMIT = 1024 * 1024
const ITERATIONS = 600000
const encoder = new TextEncoder()
const fields = ['ciphertext', 'format', 'iterations', 'kdf', 'nonce', 'salt', 'version']
function encode(bytes: Uint8Array): string {
  let text = ''
  for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192))
  return btoa(text)
}
function decode(text: unknown, length?: number): Uint8Array<ArrayBuffer> {
  if (typeof text !== 'string' || !text.length || text.length > ARCHIVE_LIMIT || text.length % 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) throw new Error('Invalid encrypted archive')
  const bytes = Uint8Array.from(atob(text), c => c.charCodeAt(0))
  if (encode(bytes) !== text || (length !== undefined && bytes.length !== length)) throw new Error('Invalid encrypted archive')
  return bytes
}
function requireCrypto() {
  if (!globalThis.crypto?.subtle) throw new Error('Encrypted archives require HTTPS or localhost')
}
async function derive(passphrase: string, salt: Uint8Array<ArrayBuffer>) {
  const bytes = encoder.encode(passphrase)
  if (bytes.length < 12 || bytes.length > 1024) { bytes.fill(0); throw new Error('Use a passphrase between 12 and 1024 UTF-8 bytes') }
  try {
    const material = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveKey'])
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  } finally { bytes.fill(0) }
}
export function validateEnvelope(value: unknown, kind: ArchiveKind): SecureEnvelope {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid encrypted archive')
  const envelope = value as SecureEnvelope
  if (Object.keys(envelope).sort().join(',') !== fields.join(',') || envelope.format !== `sb-easy.${kind}` || envelope.version !== 1 || envelope.kdf !== 'pbkdf2-sha256' || envelope.iterations !== ITERATIONS || encoder.encode(JSON.stringify(envelope)).length > ARCHIVE_LIMIT) throw new Error('Unsupported or oversized encrypted archive')
  decode(envelope.salt, 16); decode(envelope.nonce, 12)
  if (decode(envelope.ciphertext).length < 17) throw new Error('Invalid encrypted archive')
  return envelope
}
export async function encryptArchive(payload: unknown, passphrase: string, kind: ArchiveKind = 'preferences'): Promise<SecureEnvelope> {
  requireCrypto()
  const plain = encoder.encode(JSON.stringify(payload))
  if (plain.length > Math.floor((ARCHIVE_LIMIT - 512) / 4) * 3 - 16) throw new Error('Archive exceeds 1 MiB')
  const salt = crypto.getRandomValues(new Uint8Array(16)), nonce = crypto.getRandomValues(new Uint8Array(12))
  try {
    const key = await derive(passphrase, salt)
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128, additionalData: encoder.encode(`sb-easy/${kind}/v1`) }, key, plain)
    return { format: `sb-easy.${kind}`, version: 1, kdf: 'pbkdf2-sha256', iterations: ITERATIONS, salt: encode(salt), nonce: encode(nonce), ciphertext: encode(new Uint8Array(ciphertext)) }
  } finally { plain.fill(0) }
}
export async function decryptArchive(value: unknown, passphrase: string, kind: ArchiveKind = 'preferences'): Promise<unknown> {
  requireCrypto()
  const envelope = validateEnvelope(value, kind)
  const key = await derive(passphrase, decode(envelope.salt, 16))
  let plain: ArrayBuffer
  try {
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(envelope.nonce, 12), tagLength: 128, additionalData: encoder.encode(`sb-easy/${kind}/v1`) }, key, decode(envelope.ciphertext))
  } catch { throw new Error('Incorrect passphrase or damaged encrypted archive') }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain)) }
  finally { new Uint8Array(plain).fill(0) }
}
