import test from 'node:test'
import assert from 'node:assert/strict'
import { validParams, validResult, type TailscaleEndpoint, type TailscaleStatus } from '../src/lib/protocol.js'
import { tailscaleDisplay, tailscaleEndpointDisplay } from '../src/lib/tailscale.js'

const endpoint: TailscaleEndpoint = {
  tag: 'sb-easy-tailscale', backend_state: 'Running', network_name: 'example.net',
  self: { hostname: 'company-pc', dns_name: 'company-pc.example.ts.net.', ips: ['100.64.1.2', 'fd7a:115c:a1e0::12'], online: true, expired: false },
}
const connected: TailscaleStatus = { configured: true, active: true, available: true, endpoints: [endpoint] }
const context = { supported: true, connected: true, running: true, issue: '' }

test('Tailscale status accepts bounded display fields and no arbitrary request params', () => {
  assert.equal(validParams('tailscale.status', {}), true)
  assert.equal(validParams('tailscale.status', { path: '/status' }), false)
  assert.equal(validResult('tailscale.status', connected), true)
  assert.equal(validResult('tailscale.status', { ...connected, endpoints: [{ ...endpoint, self: null }] }), true)
  assert.equal(validResult('tailscale.status', { configured: false, active: false, available: false, endpoints: [] }), true)
})

test('Tailscale projection rejects secrets, malformed state and unbounded network data', () => {
  const invalid = [
    { ...connected, auth_key: 'must-never-reach-the-browser' },
    { ...connected, endpoints: [{ ...endpoint, auth_url: 'https://example.test/login' }] },
    { ...connected, endpoints: [{ ...endpoint, self: { ...endpoint.self, private_key: 'hidden' } }] },
    { ...connected, active: 'true' },
    { ...connected, endpoints: Array.from({ length: 33 }, () => endpoint) },
    { ...connected, endpoints: [{ ...endpoint, network_name: 'invalid\0name' }] },
    { ...connected, endpoints: [{ ...endpoint, self: { ...endpoint.self, ips: ['not an IP address'] } }] },
    { ...connected, endpoints: [{ ...endpoint, self: { ...endpoint.self, online: undefined } }] },
  ]
  for (const value of invalid) assert.equal(validResult('tailscale.status', value), false)
})

test('downloaded configuration and a running core never imply Tailscale online', () => {
  assert.equal(tailscaleDisplay({ ...connected, active: false, available: false, endpoints: [] }, context).label, '待应用')
  assert.equal(tailscaleDisplay(connected, { ...context, running: false }).label, '未启动')
  assert.equal(tailscaleDisplay({ ...connected, available: false }, context).label, '状态暂不可用')
  assert.equal(tailscaleDisplay({ ...connected, available: false, error: { code: 'UNAVAILABLE', message: 'Tailscale status is temporarily unavailable' } }, context).detail, 'Tailscale 配置已加载，暂时无法读取连接状态，请稍后刷新。')
  assert.equal(tailscaleDisplay({ ...connected, endpoints: [] }, context).label, '等待初始化')
})

test('online requires live Running state, online evidence, and unexpired identity', () => {
  assert.equal(tailscaleEndpointDisplay(endpoint).tone, 'ready')
  assert.equal(tailscaleEndpointDisplay({ ...endpoint, self: { ...endpoint.self!, online: false } }).label, '离线')
  assert.equal(tailscaleEndpointDisplay({ ...endpoint, self: { ...endpoint.self!, expired: true } }).label, '登录已过期')
  assert.notEqual(tailscaleEndpointDisplay({ ...endpoint, self: null }).tone, 'ready')
  assert.notEqual(tailscaleEndpointDisplay({ ...endpoint, backend_state: 'unexpected-new-state' }).tone, 'ready')
})

test('login, approval, initialization and stop states have distinct guidance', () => {
  for (const [state, label] of [['NeedsLogin', '需要登录'], ['NeedsMachineAuth', '等待设备批准'], ['Starting', '正在连接'], ['NoState', '等待初始化'], ['Stopped', '已停止']]) {
    assert.equal(tailscaleEndpointDisplay({ ...endpoint, backend_state: state! }).label, label)
  }
})

test('failed refresh, unavailable service and unsupported service suppress old online state', () => {
  assert.equal(tailscaleDisplay(connected, { ...context, issue: '读取失败' }).label, '状态暂不可用')
  assert.notEqual(tailscaleDisplay(connected, { ...context, connected: false }).tone, 'ready')
  assert.equal(tailscaleDisplay(connected, { ...context, supported: false }).label, '服务需要更新')
  assert.notEqual(tailscaleDisplay(null, context).tone, 'ready')
})

test('removing the candidate configuration does not hide the still-running Tailscale connection', () => {
  assert.equal(tailscaleDisplay({ ...connected, configured: false }, context).label, '已连接')
  assert.equal(tailscaleDisplay({ configured: false, active: false, available: false, endpoints: [] }, context).label, '未配置')
})

test('multiple endpoints only show a fully connected summary when all endpoints are online', () => {
  assert.equal(tailscaleDisplay({ ...connected, endpoints: [endpoint, { ...endpoint, backend_state: 'NeedsMachineAuth' }] }, context).label, '等待设备批准')
})
