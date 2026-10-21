import assert from 'node:assert/strict'
import test from 'node:test'
import { NativeBridge, type HostMessage, type WebViewTransport } from '../src/lib/bridge.js'
import { validParams, validResult } from '../src/lib/protocol.js'
import { dataSourceStatus, fieldSourceLabel, flagLabel, infoLabel, listCheckLabel, measurementLabel, probeErrorLabel, sourceDate, sourceForField, type IpCheckInfo, type IpCheckState } from '../src/lib/ipcheck.js'

// Explicit fixtures: these are protocol examples, never shown as live measurements.
const partial: IpCheckState = {
  phase: 'partial', error: '',
  results: [{ node: 'Fixture node', checked_at: '2026-10-13T04:00:00+00:00', ipv6_requested: true,
    ipv4: { status: 'ok', ip: '8.8.8.8', ip_info: { status: 'unknown', reason: 'blocked', http_status: 403, fields: {} }, ip_info_cached: false },
    ipv6: { status: 'unknown', reason: 'echo_connection_failed' } }],
  summary: { status: 'partial', node_count: 1, processed_count: 1, measured_count: 1, info_count: 0, complete_count: 0 },
}
const catalog = { nodes: [{ tag: 'Fixture node', type: 'trojan', source: 'Fixture subscription' }], interfaces: [{ name: 'Ethernet' }], default_interface: 'Ethernet' }
const offlineInfo: IpCheckInfo = {
  provider: 'sb-easy-offline', status: 'ok', partial: false, queried_ip: '8.8.8.8',
  database: { version: 'fixture-2026-10', generated_at: '2026-10-13T04:00:00Z' },
  fields: { country_code: 'US', asn: 'AS15169', organization: 'Fixture network', privacy: { is_datacenter: true, is_vpn: null, is_tor: null } },
  sources: [
    { id: 'fixture-geo', name: 'Fixture country source', url: 'https://example.com/geo', license: 'Fixture license', updated_at: '2026-10-01', retrieved_at: '2026-10-13', status: 'ready', families: [4, 6] },
    { id: 'fixture-list', name: 'Fixture network list', url: 'https://example.com/list', license: 'Fixture license', updated_at: '2026-10-13', retrieved_at: '2026-10-13', status: 'ready', families: [4] },
  ],
  checks: [
    { id: 'datacenter', status: 'listed', source: 'fixture-list', network: '8.8.8.0/24', updated_at: '2026-10-13' },
    { id: 'vpn', status: 'not_listed', source: 'fixture-list' },
    { id: 'tor', status: 'not_listed', source: 'fixture-list' },
  ],
  field_sources: { country: 'fixture-geo', asn: 'fixture-geo', organization: 'fixture-geo' },
}
function withInfo(info: unknown): unknown {
  return { ...partial, results: [{ ...partial.results[0], ipv4: { status: 'ok', ip: '8.8.8.8', ip_info: info } }] }
}

test('offline results preserve field attribution and distinguish not listed from unknown', () => {
  assert.equal(validResult('ipcheck.snapshot', withInfo(offlineInfo)), true)
  assert.equal(infoLabel(offlineInfo), '中心公开数据')
  assert.equal(sourceForField(offlineInfo, 'country')?.name, 'Fixture country source')
  assert.equal(listCheckLabel(offlineInfo.checks?.[0]), '命中名单')
  assert.equal(listCheckLabel(offlineInfo.checks?.[1]), '未命中此名单')
  assert.equal(listCheckLabel(undefined), '未知')
  assert.equal(offlineInfo.fields?.privacy?.is_vpn, null)
})

test('missing, stale and unsupported databases do not conceal successful exit measurements', () => {
  const unavailable: IpCheckInfo = {
    ...offlineInfo, status: 'unknown', partial: true, fields: {}, field_sources: {}, database: undefined,
    sources: offlineInfo.sources?.map(source => ({ ...source, status: 'missing', families: [], updated_at: null })),
    checks: [{ id: 'datacenter', status: 'unavailable', source: 'fixture-list', updated_at: null }],
  }
  assert.equal(validResult('ipcheck.snapshot', withInfo(unavailable)), true)
  assert.equal(infoLabel(unavailable), '中心公开数据 · 部分资料未知')
  assert.equal(listCheckLabel(unavailable.checks?.[0]), '名单不可用')
  assert.equal(dataSourceStatus(unavailable.sources![0]), '未安装')
  assert.equal(sourceDate(null), '日期未知')
  assert.equal(sourceDate('not-a-date'), '日期未知')
  assert.match(fieldSourceLabel({ ...offlineInfo.sources![0], status: 'stale' }), /已过期$/)
  assert.equal(measurementLabel({ status: 'ok', ip: '8.8.8.8', ip_info: unavailable }), '8.8.8.8')
  for (const status of ['stale', 'unsupported'] as const) {
    const check = { id: 'vpn' as const, status, source: 'fixture-list' }
    assert.equal(validResult('ipcheck.snapshot', withInfo({ ...offlineInfo, partial: true, checks: [check] })), true)
    assert.match(listCheckLabel(check), /过期|不支持/)
  }
})

test('offline schema rejects ambiguous flags, broken attribution and malformed list results', () => {
  for (const info of [
    { ...offlineInfo, partial: 'false' },
    { ...offlineInfo, checks: undefined },
    { ...offlineInfo, sources: undefined },
    { ...offlineInfo, fields: { privacy: { is_vpn: false } } },
    { ...offlineInfo, checks: [{ id: 'vpn', status: 'safe', source: 'fixture-list' }] },
    { ...offlineInfo, checks: [{ id: 'vpn', status: 'listed', source: 'absent-source' }] },
    { ...offlineInfo, checks: [offlineInfo.checks![0], offlineInfo.checks![0]] },
    { ...offlineInfo, field_sources: { country: 'absent-source' } },
    { ...offlineInfo, field_sources: { score: 'fixture-list' } },
    { ...offlineInfo, database: { version: 'fixture', generated_at: null } },
    { ...offlineInfo, sources: [{ ...offlineInfo.sources![0], families: [4, 4] }] },
    { ...offlineInfo, sources: [{ ...offlineInfo.sources![0], url: 'javascript:alert(1)' }] },
    { ...offlineInfo, sources: [{ ...offlineInfo.sources![0], status: 'fresh' }] },
    { ...offlineInfo, sources: [offlineInfo.sources![0], offlineInfo.sources![0]] },
  ]) assert.equal(validResult('ipcheck.snapshot', withInfo(info)), false)
})

test('legacy plugin remains removable while a required reinstall prevents enabling it', () => {
  const legacy = { id: 'ip-check', name: 'IP 检测', version: '1.0.0', installed: true, enabled: false, running: false, failed: false, needs_update: true }
  assert.equal(validResult('extensions.list', { extensions: [legacy] }), true)
  assert.equal(validResult('extensions.change', { extensions: [{ ...legacy, needs_update: false }] }), true)
  for (const changes of [{ needs_update: 'yes' }, { enabled: true }, { running: true }, { installed: false }]) {
    assert.equal(validResult('extensions.list', { extensions: [{ ...legacy, ...changes }] }), false)
  }
  assert.equal(validParams('extensions.change', { id: 'ip-check', action: 'remove' }), true)
})

test('Center check sends selected tags only without accepting config or system proxy changes', () => {
  const params = { tags: ['Fixture node'], ipv6: true }
  assert.equal(validParams('ipcheck.start', params), true)
  for (const invalid of [
    { ...params, tags: [] }, { ...params, tags: ['same', 'same'] },
    { ...params, tags: Array.from({ length: 101 }, (_, i) => `node-${i}`) },
    { ...params, tags: ['node\u0000'] }, { ...params, tags: ['界'.repeat(200)] },
    { ...params, interface: '' }, { ...params, interface: 'Ethernet\n' },
    { ...params, ipv6: 'true' }, { ...params, config: { password: 'secret' } },
    { ...params, switch_proxy: true },
  ]) assert.equal(validParams('ipcheck.start', invalid), false)
  for (const method of ['ipcheck.catalog', 'ipcheck.snapshot', 'ipcheck.cancel'] as const) {
    assert.equal(validParams(method, {}), true)
    assert.equal(validParams(method, { all: true }), false)
  }
  assert.equal(validParams('extensions.install', { id: 'ip-check' }), true)
})

test('IP check catalog validates choices and never defaults to a missing interface', () => {
  assert.equal(validResult('ipcheck.catalog', catalog), true)
  assert.equal(validResult('ipcheck.catalog', { nodes: [], interfaces: [], default_interface: '' }), true)
  assert.equal(validResult('ipcheck.catalog', { ...catalog, default_interface: 'missing' }), false)
  assert.equal(validResult('ipcheck.catalog', { ...catalog, nodes: [catalog.nodes[0], catalog.nodes[0]] }), false)
  assert.equal(validResult('ipcheck.catalog', { ...catalog, nodes: [{ tag: 'x', type: 'socks', source: 1 }] }), false)
})

test('403 metadata refusal preserves the measured exit and is not a bad-node or clean-IP verdict', () => {
  assert.equal(validResult('ipcheck.snapshot', partial), true)
  assert.equal(measurementLabel(partial.results[0].ipv4), '8.8.8.8')
  assert.equal(infoLabel(partial.results[0].ipv4?.ip_info), '资料接口拒绝（403）')
  assert.equal(flagLabel(undefined), '未知')
  assert.equal(flagLabel(null), '未知')
  assert.equal(flagLabel(false), '否')
  assert.equal(flagLabel(true), '是')
  assert.equal(measurementLabel(partial.results[0].ipv6, 6), '本次 IPv6 路径未成功')
  assert.equal(measurementLabel(undefined, 6, false), '未检测')
  assert.equal(infoLabel({ status: 'unknown', reason: 'rate_limited', http_status: 429 }), '资料接口限流（429）')
})

test('incremental, cancelled and unavailable states retain previous measured results', () => {
  const running = { ...partial, phase: 'running', summary: { ...partial.summary, node_count: 3 } }
  assert.equal(validResult('ipcheck.start', running), true)
  assert.equal(validResult('ipcheck.cancel', { ...running, cancel_requested: true }), true)
  assert.equal(validResult('ipcheck.snapshot', { ...running, phase: 'cancelled' }), true)
  assert.equal(validResult('ipcheck.snapshot', { phase: 'idle', results: [], error: '', summary: { status: 'failed', node_count: 0, processed_count: 0, measured_count: 0, info_count: 0, complete_count: 0 } }), true)
  for (const invalid of [
    { ...partial, phase: 'success' }, { ...partial, error: null }, { ...partial, cancel_requested: 1 },
    { ...partial, summary: { ...partial.summary, processed_count: 2 } },
    { ...partial, summary: { ...partial.summary, measured_count: 0, info_count: 1 } },
    { ...partial, summary: { ...partial.summary, node_count: 101 } },
    { ...partial, results: [{ ...partial.results[0], ipv4: { status: 'unknown', ip: '8.8.8.8' } }] },
    { ...partial, results: [{ ...partial.results[0], ipv4: { status: 'ok', ip: '8.8.8.8', ip_info: { status: 'ok', fields: { privacy: { is_datacenter: 'false' } } } } }] },
  ]) assert.equal(validResult('ipcheck.snapshot', invalid), false)
})

test('worker termination reports an actionable failure without erasing earlier results', () => {
  assert.equal(validResult('ipcheck.snapshot', { ...partial, phase: 'failed', error: 'probe_worker_stopped' }), true)
  assert.equal(probeErrorLabel('probe_worker_stopped'), '检测进程已停止，可以重新开始')
  assert.equal(probeErrorLabel('probe_runtime_failed'), '检测进程运行失败，请重试')
})

class Transport implements WebViewTransport {
  messages: { id: string; method: string; params: unknown }[] = []
  listener?: (event: HostMessage) => void
  postMessage(value: unknown): void { this.messages.push(value as typeof this.messages[number]) }
  addEventListener(_type: 'message', listener: (event: HostMessage) => void): void { this.listener = listener }
  removeEventListener(): void { this.listener = undefined }
  reply(index: number, result: unknown): void { this.listener?.({ data: { id: this.messages[index].id, ok: true, result } }) }
}

test('bridge preserves partial results and does not automatically retry a start on BUSY', async () => {
  const transport = new Transport()
  const bridge = new NativeBridge(transport)
  const start = bridge.request('ipcheck.start', { tags: ['Fixture node'], ipv6: false })
  transport.listener?.({ data: { id: transport.messages[0].id, ok: false, error: { code: 'BUSY', message: 'busy' } } })
  await assert.rejects(start, { code: 'BUSY' })
  await new Promise(resolve => setTimeout(resolve, 220))
  assert.equal(transport.messages.length, 1)
  const snapshot = bridge.request('ipcheck.snapshot')
  transport.reply(1, partial)
  assert.deepEqual(await snapshot, partial)
  assert.deepEqual(transport.messages.map(item => item.method), ['ipcheck.start', 'ipcheck.snapshot'])
  bridge.dispose()
})

test('bridge rejects malformed IP check results rather than displaying a success', async () => {
  const transport = new Transport()
  const bridge = new NativeBridge(transport)
  const snapshot = bridge.request('ipcheck.snapshot')
  transport.reply(0, { ...partial, summary: { ...partial.summary, processed_count: '1' } })
  await assert.rejects(snapshot, { code: 'invalid_response' })
  bridge.dispose()
})


test('daily center cache is read-only and validates timestamps and measurements', () => {
  const entry = { status: 'ok', attempted_at: 1700000000, next_check_at: 1700086400, result: { checked_at: '2026-10-13T00:00:00Z', ipv4: { status: 'ok', ip: '8.8.8.8' } }, last_success: null }
  const cache = { nodes: { 'Center Node': entry }, running: false, error: '', interval_seconds: 86400 }
  assert.equal(validParams('ipcheck.daily', {}), true)
  assert.equal(validParams('ipcheck.daily', { tags: ['Center Node'] }), false)
  assert.equal(validResult('ipcheck.daily', cache), true)
  assert.equal(validResult('ipcheck.daily', { ...cache, nodes: { node: { ...entry, attempted_at: -1 } } }), false)
  assert.equal(validResult('ipcheck.daily', { ...cache, nodes: { node: { ...entry, result: { ipv4: { status: 'ok' } } } } }), false)
})
