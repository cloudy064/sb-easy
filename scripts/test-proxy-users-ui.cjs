#!/usr/bin/env node
// Isolated browser smoke of the C11 API + built Vue app. A runtime capability
// fixture exercises the control plane; this does not claim data-plane coverage.
const assert = require('node:assert/strict')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')
const net = require('node:net')
const { spawn } = require('node:child_process')
const { once } = require('node:events')
const { randomBytes } = require('node:crypto')

async function main() {
  const repo = path.resolve(__dirname, '..')
  const serverBinary = path.resolve(process.argv[2] || path.join(repo, 'build/c-proxy-users/sb-easy-c-server'))
  const { chromium } = require(process.env.SB_EASY_PLAYWRIGHT_PACKAGE || 'playwright')
  const scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'sb-proxy-ui-'))
  const socket = net.createServer().listen(0, '127.0.0.1')
  await once(socket, 'listening')
  const port = socket.address().port
  await new Promise(resolve => socket.close(resolve))
  const origin = `http://127.0.0.1:${port}`
  const password = randomBytes(24).toString('hex'), agent = randomBytes(24).toString('hex')
  const child = spawn(serverBinary, [], { cwd: repo, env: { ...process.env,
    DATABASE_URL: `sqlite:${path.join(scratch, 'panel.db')}`, MIGRATIONS_DIR: path.join(repo, 'migrations'),
    BIND_ADDR: `127.0.0.1:${port}`, PUBLIC_SERVER: origin, STATIC_DIR: path.join(repo, 'frontend/dist'),
    JWT_SECRET: randomBytes(32).toString('hex'), ADMIN_PASSWORD: password, AGENT_TOKEN: agent,
    WG_ENABLED: 'false', SINGBOX_MANAGED: 'false', SUBSCRIPTION_AUTO_REFRESH: 'false', LOG_LEVEL: 'warn',
  }, stdio: ['ignore', 'ignore', 'pipe'] })
  let logs = ''; child.stderr.on('data', data => { logs += data.toString() })
  let browser
  try {
    for (let i = 0; i < 100; ++i) {
      if (child.exitCode !== null) throw new Error(`Server exited: ${logs}`)
      try { if ((await fetch(`${origin}/api/health`)).ok) break } catch {}
      await new Promise(resolve => setTimeout(resolve, 100))
    }
    const status = await fetch(`${origin}/api/agent/status`, { method: 'POST', headers: { Authorization: `Bearer ${agent}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ capabilities: ['proxy_users_v1'] }) })
    assert.equal(status.status, 200)
    browser = await chromium.launch({ headless: true, ...(process.env.SB_EASY_CHROMIUM ? { executablePath: process.env.SB_EASY_CHROMIUM } : {}) })
    const context = await browser.newContext({ viewport: { width: 1365, height: 1000 }, locale: 'en-US' })
    const page = await context.newPage(), errors = []
    page.on('pageerror', error => errors.push(error.message))
    await page.goto(`${origin}/login`)
    await page.locator('input[type=password]').fill(password)
    await page.locator('button[type=submit]').click()
    await page.waitForURL(`${origin}/`)
    await page.getByRole('link', { name: 'Proxy users', exact: true }).click()
    await page.getByRole('button', { name: 'Configure node', exact: true }).click()
    let modal = page.locator('.modal')
    await modal.locator('select').selectOption('self')
    await modal.locator('input').nth(0).fill('node.example')
    await modal.locator('input').nth(1).fill('127.0.0.1')
    await modal.locator('input[type=checkbox]').check()
    await modal.getByRole('button', { name: 'Save', exact: true }).click()
    await modal.waitFor({ state: 'hidden' })
    await page.getByRole('button', { name: 'Add proxy user', exact: true }).click()
    modal = page.locator('.modal')
    await modal.locator('input').nth(0).fill('Browser lifecycle user')
    await modal.locator('input').nth(1).fill('1048576')
    await modal.locator('fieldset input[type=checkbox]').check()
    await modal.getByRole('button', { name: 'Save', exact: true }).click()
    await modal.waitFor({ state: 'hidden' })
    await page.getByText('Browser lifecycle user', { exact: true }).waitFor()
    page.on('dialog', dialog => dialog.accept())
    await page.getByRole('button', { name: 'Issue claim link', exact: true }).click()
    const secret = page.locator('textarea[aria-label="Credential URL"]')
    await secret.waitFor()
    const claimLink = await secret.inputValue()
    assert.match(claimLink, /\/proxy-access#token=/)
    await page.getByRole('button', { name: 'Dismiss', exact: true }).click()
    const visitor = await browser.newContext({ viewport: { width: 390, height: 844 }, locale: 'en-US' })
    const access = await visitor.newPage()
    access.on('pageerror', error => errors.push(error.message))
    await access.goto(claimLink)
    await access.getByRole('heading', { name: 'Browser lifecycle user', exact: true }).waitFor()
    assert.equal(new URL(access.url()).hash, '')
    assert.equal(await access.evaluate(() => localStorage.getItem('sb-easy-token')), null)
    await access.locator('#new-device-name').fill('Browser phone')
    await access.getByRole('button', { name: /Create device subscription/ }).click()
    const subscription = access.locator('textarea[aria-label="Subscription URL"]')
    await subscription.waitFor()
    const subscriptionUrl = await subscription.inputValue()
    let response = await fetch(subscriptionUrl), config = await response.json()
    assert.equal(response.status, 200); assert.equal(config.outbounds.length, 1)
    assert.equal(config.outbounds[0].method, '2022-blake3-aes-128-gcm')
    const storage = await access.evaluate(() => ({ local: Object.values(localStorage), session: Object.values(sessionStorage) }))
    assert(!JSON.stringify(storage).includes(new URL(subscriptionUrl).searchParams.get('token')))
    access.on('dialog', dialog => dialog.accept())
    await access.getByRole('button', { name: 'Revoke', exact: true }).click()
    await access.locator('.device-row').waitFor({ state: 'hidden' })
    response = await fetch(subscriptionUrl); assert.equal(response.status, 401)
    await page.getByRole('button', { name: 'Refresh', exact: true }).click()
    await page.locator('.user-row .device-row').waitFor({ state: 'hidden' })
    await page.getByRole('button', { name: 'Reset quota period', exact: true }).click()
    await page.getByText(/This controller is waiting for prior authorization to expire/).waitFor()
    await page.getByRole('button', { name: 'Delete', exact: true }).click()
    await page.locator('.user-row').waitFor({ state: 'hidden' })
    assert.deepEqual(errors, [])
    console.log('PASS: browser admin ingress/user creation, one-time claim, isolated mobile self-service, subscription, revoke and reset/delete')
    console.log('Control-plane UI smoke only; runtime capability report uses a fixture.')
  } finally {
    if (browser) await browser.close()
    const stopped = once(child, 'exit')
    if (child.exitCode === null) { child.kill('SIGTERM'); await stopped }
    await fs.rm(scratch, { recursive: true, force: true })
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1 })
