#!/usr/bin/env node
// Real C server and built panel, private DB and loopback ports only.
const assert = require('node:assert/strict')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')
const net = require('node:net')
const { once } = require('node:events')
const { spawn } = require('node:child_process')
const { randomBytes } = require('node:crypto')

async function main() {
  const { chromium } = require(process.env.SB_EASY_PLAYWRIGHT_PACKAGE || 'playwright')
  const repo = path.resolve(__dirname, '..')
  const scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'sb-config-ui-'))
  const socket = net.createServer().listen(0, '127.0.0.1')
  await once(socket, 'listening')
  const port = socket.address().port
  await new Promise(resolve => socket.close(resolve))
  const origin = `http://127.0.0.1:${port}`
  const password = randomBytes(24).toString('hex')
  const child = spawn(path.resolve(process.argv[2] || path.join(repo, 'build/c-product-audit/sb-easy-c-server')), [], {
    cwd: repo, env: { PATH: process.env.PATH, HOME: scratch,
      BIND_ADDR: `127.0.0.1:${port}`, DATABASE_URL: `sqlite:${path.join(scratch, 'panel.db')}`,
      MIGRATIONS_DIR: path.join(repo, 'migrations'), PUBLIC_SERVER: origin, STATIC_DIR: path.join(repo, 'frontend/dist'),
      JWT_SECRET: randomBytes(32).toString('hex'), ADMIN_PASSWORD: password,
      WG_ENABLED: 'false', SINGBOX_MANAGED: 'false', SUBSCRIPTION_AUTO_REFRESH: 'false', LOG_LEVEL: 'warn',
    }, stdio: ['ignore', 'ignore', 'pipe'],
  })
  let logs = '', browser
  child.stderr.on('data', data => { logs += data.toString() })
  try {
    let ready = false
    for (let i = 0; i < 100; ++i) {
      if (child.exitCode !== null) throw new Error(`Server exited: ${logs}`)
      try { if ((await fetch(origin + '/api/health')).ok) { ready = true; break } } catch {}
      await new Promise(resolve => setTimeout(resolve, 100))
    }
    assert(ready)
    const login = await fetch(origin + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }) })
    const { token } = await login.json()
    async function api(url, body, method) {
      const response = await fetch(origin + '/api' + url, { method: method || (body ? 'POST' : 'GET'),
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
      const value = await response.json()
      assert.equal(response.status, 200, JSON.stringify(value))
      return value
    }
    const host = await api('/hosts', { name: 'Config sync browser fixture', profile_id: 'default', capabilities: { runs_singbox: false, is_wg_member: false } })
    const endpoint = `/hosts/${host.id}/config-state`
    browser = await chromium.launch({ headless: true, ...(process.env.SB_EASY_CHROMIUM ? { executablePath: process.env.SB_EASY_CHROMIUM } : {}) })
    const page = await browser.newPage({ viewport: { width: 1365, height: 1000 } })
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    await page.addInitScript(() => localStorage.setItem('sb-easy-locale', 'en'))
    await page.goto(origin + '/login')
    await page.locator('input[type=password]').fill(password)
    await page.locator('button[type=submit]').click()
    await page.waitForURL(origin + '/')
    await page.goto(origin + '/devices')
    await page.getByRole('button', { name: 'Add device', exact: true }).click()
    const enrollment = page.locator('.enrollment-modal')
    await enrollment.locator('input').first().fill('Shared default with Tailscale')
    await enrollment.locator('.tailscale-settings input[type=checkbox]').first().check()
    const createdResponse = page.waitForResponse(response => response.url() === origin + '/api/hosts' && response.request().method() === 'POST')
    await enrollment.getByRole('button', { name: 'Create authorization', exact: true }).click()
    const created = await (await createdResponse).json()
    await enrollment.getByText('Device authorization is ready', { exact: true }).waitFor()
    assert.equal(created.profile_id, 'default')
    assert.equal(created.tailscale.enabled, true)
    assert.deepEqual((await api(`/hosts/${created.id}/config-state`)).patch, {})
    await page.goto(`${origin}/devices/${created.id}`)
    await page.locator('.page-header').getByRole('button', { name: 'Edit', exact: true }).click()
    const management = page.locator('.modal-wide')
    await management.locator('input').first().fill('Renamed synchronized Tailscale device')
    const updatedResponse = page.waitForResponse(response => response.url() === `${origin}/api/hosts/${created.id}` && response.request().method() === 'PUT')
    await management.getByRole('button', { name: 'Save', exact: true }).click()
    const updated = await (await updatedResponse).json()
    await management.waitFor({ state: 'hidden' })
    assert.equal(updated.profile_id, 'default')
    assert.equal(updated.tailscale.enabled, true)
    assert.equal(updated.name, 'Renamed synchronized Tailscale device')
    await page.goto(`${origin}/devices/${host.id}`)
    const panel = page.locator('.sync-panel')
    const draft = panel.locator('textarea').first()
    await draft.waitFor()
    assert.deepEqual(JSON.parse(await draft.inputValue()), {})
    await draft.fill('{"log":{"level":"debug"}}')
    await panel.getByRole('button', { name: 'Save to server', exact: true }).click()
    await page.waitForFunction(() => !document.querySelector('.sync-panel button').disabled)
    assert.deepEqual((await api(endpoint)).patch, { log: { level: 'debug' } })

    await draft.fill('{"log":{"level":"error"}}')
    const current = await api(endpoint)
    await api(endpoint, { base_version: current.base_version, patch_version: current.patch_version, patch: { log: { level: 'warn' } }, agent_settings: {} }, 'PUT')
    await panel.getByRole('button', { name: 'Save to server', exact: true }).click()
    await panel.getByText('Latest server changes', { exact: true }).waitFor()
    assert.deepEqual(JSON.parse(await draft.inputValue()), { log: { level: 'error' } })
    assert.deepEqual((await api(endpoint)).patch, { log: { level: 'warn' } })
    await panel.getByRole('button', { name: 'Use server version', exact: true }).click()
    assert.deepEqual(JSON.parse(await draft.inputValue()), { log: { level: 'warn' } })
    await panel.getByRole('button', { name: 'Use default (clear draft patch)', exact: true }).click()
    await panel.getByRole('button', { name: 'Save to server', exact: true }).click()
    await page.waitForFunction(() => !document.querySelector('.sync-panel button').disabled)
    assert.deepEqual((await api(endpoint)).patch, {})
    assert((await api(endpoint)).patch_version > current.patch_version)
    await page.goto(origin + '/profiles')
    const defaultCard = page.locator('.profile-card').filter({ has: page.locator('.profile-id').filter({ hasText: 'default' }) })
    await defaultCard.getByRole('button', { name: 'Edit', exact: true }).click()
    const modal = page.locator('.modal')
    await modal.locator('input').first().fill('Shared default browser fixture')
    await modal.getByRole('button', { name: 'Save', exact: true }).click()
    await modal.waitFor({ state: 'hidden' })
    assert.equal((await api('/config/default')).profile.name, 'Shared default browser fixture')
    await defaultCard.getByRole('button', { name: 'Edit', exact: true }).click()
    await modal.locator('input').first().fill('Unsaved local default draft')
    const base = await api('/config/default')
    await api('/config/default', { base_version: base.base_version,
      profile: { ...base.profile, name: 'Concurrent server default', template: JSON.parse(base.profile.template) } }, 'PUT')
    await modal.getByRole('button', { name: 'Save', exact: true }).click()
    await modal.locator('.json-err').waitFor()
    assert.equal(await modal.locator('input').first().inputValue(), 'Unsaved local default draft')
    assert.equal((await api('/config/default')).profile.name, 'Concurrent server default')
    assert.deepEqual(errors, [])
    console.log('PASS shared-default/Tailscale enrollment, panel patch save/conflict/reset and default-editor version checks')
  } finally {
    if (browser) await browser.close()
    if (child.exitCode === null) { const exited = once(child, 'exit'); child.kill('SIGTERM'); await exited }
    await fs.rm(scratch, { recursive: true, force: true })
  }
}
main().catch(error => { console.error(error); process.exitCode = 1 })
