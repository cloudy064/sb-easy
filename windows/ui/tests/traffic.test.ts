import test from 'node:test'
import assert from 'node:assert/strict'
import { groupTraffic, trafficDomain } from '../src/lib/traffic.js'
import { validResult, validParams } from '../src/lib/protocol.js'

test('domain grouping follows public and private suffixes and preserves IP hosts', () => {
  assert.equal(trafficDomain('API.Example.CO.UK.'), 'example.co.uk')
  assert.equal(trafficDomain('a.owner.github.io'), 'owner.github.io')
  assert.equal(trafficDomain('10.59.32.2'), '10.59.32.2')
  assert.equal(trafficDomain(''), '未知目标')
})
test('app/domain drilldown preserves host and outbound attribution', () => {
  const rows = [
    { app:'codex.exe',host:'api.example.com',outbound:'Japan',rule:'default',upload:10,download:40,last_seen:10 },
    { app:'codex.exe',host:'api.example.com',outbound:'direct',rule:'default',upload:20,download:60,last_seen:20 },
    { app:'browser.exe',host:'www.example.com',outbound:'Japan',rule:'default',upload:5,download:50,last_seen:30 },
  ]
  const domains = groupTraffic(rows, 'domain')
  assert.equal(domains.length, 1); assert.equal(domains[0].hosts, 2); assert.equal(domains[0].download, 150)
  const app = groupTraffic(rows,'app').find(row => row.key === 'codex.exe')!
  const host = groupTraffic(app.rows,'host')[0]
  assert.equal(host.download, 100); assert.equal(groupTraffic(host.rows,'outbound').length, 2)
})
test('statistics and logs reject invalid IPC responses and unexpected parameters', () => {
  assert.equal(validParams('traffic.clear', { path:'arbitrary' }), false)
  assert.equal(validResult('logs.snapshot', { lines:['safe'] }), true)
  assert.equal(validResult('logs.snapshot', { lines:['x'.repeat(1025)] }), false)
  const value = { version:1,upload:0,download:0,sampled_at:0,cleared_at:0,limited:false,storage_ok:true,rows:[] }
  assert.equal(validResult('traffic.snapshot',value), true)
  assert.equal(validResult('traffic.snapshot',{...value,upload:-1}), false)
})
