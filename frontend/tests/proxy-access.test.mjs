import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = ts.transpileModule(readFileSync(new URL('../src/lib/proxyAccess.ts', import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { readAccess, writeAccess, proxyUrl, newAccessKey } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`)
const original = { inbounds: [{ type: 'mixed', tag: 'mixed-in', listen_port: 7890 }], route: { rules: [{ domain_suffix: ['google.com'], outbound: 'Other' }], final: 'Other' }, extra: { keep: true } }
const access = { enabled: true, listen: '127.0.0.1', port: 1081, users: [{ username: 'google', password: 'secret:@/?', outbound: 'Google' }, { username: 'claude', password: 'secret2', outbound: 'Claude' }] }
const updated = writeAccess(original, access, ['Google', 'Claude'])
assert.deepEqual(readAccess(updated), access)
assert.equal(original.inbounds.length, 1)
assert.equal(updated.route.rules[0].auth_user, 'google')
assert.equal(updated.route.rules[2].action, 'reject')
assert.deepEqual(writeAccess(updated, { ...access, enabled: false }, []), original)
assert.deepEqual(writeAccess(updated, access, ['Google', 'Claude']), updated)
assert.throws(() => writeAccess(original, { ...access, users: [] }, []))
assert.throws(() => writeAccess(original, { ...access, port: 7890 }, ['Google', 'Claude']))
assert.throws(() => writeAccess(original, { ...access, users: [access.users[0], access.users[0]] }, ['Google']))
assert.throws(() => writeAccess(original, access, ['Google']))
assert.equal(proxyUrl('::1', 1081, access.users[0]), 'http://google:secret%3A%40%2F%3F@[::1]:1081')
assert.throws(() => proxyUrl('https://example.com/', 1081, access.users[0]))
assert.match(newAccessKey(), /^[a-f0-9]{48}$/)
console.log('Proxy access: round trip, fail-closed validation, priority, URL encoding and secure key tests passed')
const pinned = { enabled: true, listen: '127.0.0.1', port: 1081, users: [{ kind: 'node', nodeId: 'stable-id', username: 'node_stable-id', password: 'secret', outbound: 'sb-easy-node-stable-id' }] }
const pinnedConfig = writeAccess(original, pinned, [], [{ id: 'stable-id', tag: 'Old name', enabled: true }])
assert.deepEqual(readAccess(pinnedConfig), pinned)
assert.deepEqual(writeAccess(pinnedConfig, pinned, [], [{ id: 'stable-id', tag: 'New name', enabled: true }]), pinnedConfig)
assert.deepEqual(writeAccess(pinnedConfig, pinned, [], []), pinnedConfig) // preserve a deleted binding, never rebind by name
assert.throws(() => writeAccess(original, pinned, [], []))
assert.throws(() => writeAccess(original, { ...pinned, users: [{ ...pinned.users[0], outbound: 'Google' }] }, ['Google'], [{ id: 'stable-id', tag: 'Name', enabled: true }]))
console.log('Fixed identity: rename, deletion preservation, missing node and tamper tests passed')
