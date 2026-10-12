// Isolated loopback-only control plane for desktop enrollment smoke tests.
// The token and code below are test fixtures, never production credentials.
import http from 'node:http'
import net from 'node:net'
import fs from 'node:fs'
import path from 'node:path'
import { randomUUID, createHash } from 'node:crypto'

const directory = process.argv[2]
if (!directory || !path.isAbsolute(directory)) throw new Error('Expected absolute fixture output directory')
const token = `fixture-${randomUUID()}`
// Reserve an OS-assigned port until the candidate is requested. Never assume a
// developer's fixed proxy port is free or reuse another application's listener.
const proxyReservation = net.createServer()
await new Promise((resolve, reject) => {
  proxyReservation.once('error', reject)
  proxyReservation.listen(0, '127.0.0.1', resolve)
})
const proxyPort = proxyReservation.address().port
fs.writeFileSync(path.join(directory, 'fixture-proxy-port.txt'), String(proxyPort))
const receipt = { enrollments: 0, configRequests: 0, notModified: 0, rejected: 0, ruleRequests: 0, captures: 0 }
let origin
function record() { fs.writeFileSync(path.join(directory, 'fixture-receipt.json'), JSON.stringify(receipt)) }
const server = http.createServer(async (request, response) => {
  const reply = (status, body, headers = {}) => {
    record()
    response.writeHead(status, { 'Content-Type': 'application/json', ...headers })
    response.end(body == null ? '' : JSON.stringify(body))
  }
  if (request.url === '/test/connection-stream' && request.method === 'GET') {
    response.writeHead(200, { 'Content-Type': 'application/octet-stream' })
    const chunk = Buffer.alloc(4096, 's')
    const timer = setInterval(() => response.write(chunk), 100)
    response.on('close', () => clearInterval(timer))
    return
  }
  if (request.url === '/test/connection-probe' && request.method === 'GET') {
    reply(200, { fixture: 'sb-easy-connection-probe' })
    return
  }
  if (request.url === '/test/slow-rules' && request.method === 'GET') {
    receipt.ruleRequests++
    await new Promise(resolve => setTimeout(resolve, 8000))
    reply(200, { version: 3, rules: [{ domain: ['fixture.invalid'] }] })
    return
  }
  if (request.url === '/test/api/devices/enroll' && request.method === 'POST') {
    const chunks = []
    let size = 0
    for await (const chunk of request) {
      size += chunk.length
      if (size > 65536) { request.destroy(); return }
      chunks.push(chunk)
    }
    let body
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { reply(400, {}); return }
    if (body.code !== 'a'.repeat(64) || body.device?.platform !== 'windows' || receipt.enrollments > 0) {
      receipt.rejected++
      reply(400, { error: 'Invalid or already used fixture enrollment' })
      return
    }
    receipt.enrollments++
    reply(200, { server: origin, host_id: 'windows-smoke', host_name: 'Windows 开发测试设备', agent_token: token,
      profile: { id: 'fixture-profile', name: '桌面测试配置' } })
    return
  }
  if (/^\/test\/api\/agent\/captures\/[a-f0-9]{64}$/.test(request.url) && request.method === 'POST') {
    if (request.headers.authorization !== `Bearer ${token}`) { receipt.rejected++; reply(401, {}); return }
    const chunks = []; let size = 0
    for await (const chunk of request) { size += chunk.length; if (size > 768 * 1024) { request.destroy(); return }; chunks.push(chunk) }
    const data = Buffer.concat(chunks), digest = request.url.split('/').at(-1)
    if (data.length < 24 || data.readUInt32LE(0) !== 0xa1b2c3d4 || data.readUInt32LE(20) !== 101 || createHash('sha256').update(data).digest('hex') !== digest || request.headers['content-type'] !== 'application/vnd.tcpdump.pcap') { reply(400, {}); return }
    let offset = 24
    while (offset + 16 <= data.length) { const length = data.readUInt32LE(offset + 8); if (!length || length > 65535 || length !== data.readUInt32LE(offset + 12) || offset + 16 + length > data.length) { reply(400, {}); return }; offset += 16 + length }
    if (offset !== data.length) { reply(400, {}); return }
    receipt.captures++; fs.writeFileSync(path.join(directory, `${digest}.pcap`), data)
    reply(200, { ok: true, digest }); return
  }
  if (request.url === '/test/subscription' && request.method === 'GET') {
    if (request.headers.authorization || request.headers.cookie) { reply(400, {}); return }
    reply(200, [{ type: 'http', tag: 'local-test', server: '127.0.0.1', server_port: 8080 }]); return
  }
  if (['/test/api/agent/config','/test/api/agent/config?sources=1'].includes(request.url) && request.method === 'GET') {
    if (request.headers.authorization !== `Bearer ${token}`) { receipt.rejected++; reply(401, {}); return }
    receipt.configRequests++
    const override = path.join(directory, 'fixture-candidate.json')
    const overridden = fs.existsSync(override)
    const etag = overridden ? '"fixture-v2"' : '"fixture-v1"'
    if (request.headers['if-none-match'] === etag) {
      receipt.notModified++
      reply(304, null)
      return
    }
    if (proxyReservation.listening) await new Promise(resolve => proxyReservation.close(resolve))
    const candidate = overridden ? JSON.parse(fs.readFileSync(override, 'utf8').replace(/^\uFEFF/, '')) : {
      inbounds: [{ type: 'mixed', tag: 'fixture-local', listen: '127.0.0.1', listen_port: proxyPort }],
      outbounds: [{ type: 'direct', tag: 'direct' }, { type: 'trojan', tag: 'fixture-node', server: 'example.invalid', server_port: 443, password: 'fixture-password-must-never-reach-ui' }],
      route: { rules: [{ domain: ['example.invalid'], outbound: 'direct' }], final: 'direct' },
    }
    reply(200, request.url.includes('sources=1') ? { config: candidate, subscription_sources: [{ id: 'fixture-source', name: 'Fixture subscription', tags: candidate.outbounds.filter(n => n.type !== 'direct').map(n => n.tag) }] } : candidate, { ETag: etag, 'X-SB-Easy-Rule-Source': 'profile', 'X-SB-Easy-Profile-Id': 'fixture-profile' })
    return
  }
  receipt.rejected++
  reply(404, {})
})
// Loopback-only proxy for live-routing acceptance; never forwards to the Internet.
server.on('connect', (request, socket, head) => {
  if (!['api.openai.com:80', 'api.anthropic.com:80'].includes(request.url)) { socket.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return }
  const upstream = net.connect(server.address().port, '127.0.0.1', () => {
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    if (head.length) upstream.write(head)
    socket.pipe(upstream); upstream.pipe(socket)
  })
  upstream.on('error', () => socket.destroy())
  socket.on('error', () => upstream.destroy())
  socket.on('close', () => upstream.destroy())
})
server.listen(0, '127.0.0.1', () => {
  origin = `http://127.0.0.1:${server.address().port}/test`
  record()
  fs.writeFileSync(path.join(directory, 'fixture-origin.txt'), origin)
})
