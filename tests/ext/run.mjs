// Loads the real unpacked extension into Chromium (headless=new) against the real server and fake ClosedDoor, and drives
// the popup, the sign-in window, autofill, the save bar, locking and offline unlock. Also the phishing cases.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { chromium } from 'playwright-core'
import { startStack } from '../ui/devserver.mjs'
import { CHROME, OUT, launch, person, shot, signInAndSetup, watch } from '../ui/lib.mjs'
import { startSite } from './site.mjs'

const EXT_ID = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../../extension/manifest.json'), 'utf8')) && 'gfnpigdeagehjmdcmkijcmgfadlpnlbl'
const EXT_DIR = path.resolve(import.meta.dirname, '../../extension')
const PW = 'extension test master password 1'

const site = await startSite()
const stack = await startStack({ extensionIds: EXT_ID })
let failed = 0
const results = []
async function step(name, fn) {
  const t = Date.now()
  try { await fn(); console.log(`  ok   ${name} (${Date.now() - t} ms)`); results.push(['ok', name]) } catch (e) { failed++; results.push(['FAIL', name]); console.log(`  FAIL ${name}\n       ${String(e.stack || e).split('\n').slice(0, 7).join('\n       ')}`) }
}
const until = async (fn, what, ms = 10000) => { const end = Date.now() + ms; let last; while (Date.now() < end) { try { last = await fn(); if (last) return last } catch (e) { last = e } await new Promise((r) => setTimeout(r, 80)) } throw new Error('timed out waiting for ' + what + (last instanceof Error ? ': ' + last.message : '')) }

console.log('TheVault extension tests; vault', stack.url, 'site', site.port)

// 1. the person creates a vault and a login in the web app (with a normal browser)
const web = await launch()
const ana = await person(web, stack, 'ana')
await signInAndSetup(ana.page, stack, PW)
const addLogin = async (name, user, pass, url) => {
  await ana.page.goto(stack.url + '/#/new/login')
  await ana.page.locator('#f-name').fill(name)
  await ana.page.locator('#f-username').fill(user)
  await ana.page.locator('#f-password').fill(pass)
  if (url) { await ana.page.getByRole('button', { name: 'Add website' }).click(); await ana.page.getByLabel('Website address 1').fill(url) }
  await ana.page.locator('#f-totp').fill('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
  await ana.page.getByRole('button', { name: 'Save', exact: true }).click()
  await ana.page.locator('.detail h1', { hasText: name }).waitFor()
}
await addLogin('Test site', 'ana@site.test', 'S3cret!pass-0001', `http://localhost:${site.port}/`)

// 2. a second browser, with the extension loaded
const userDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-ext-'))
const ctx = await chromium.launchPersistentContext(userDir, { executablePath: CHROME, headless: false, viewport: { width: 1100, height: 800 },
  args: ['--headless=new', '--no-sandbox', `--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`] })
await ctx.addCookies([{ name: 'sso_user', value: 'ana', url: stack.sso.url }])
const problems = []
ctx.on('page', (p) => { if (!p.url().startsWith('chrome-extension://')) watch(p, problems) })
let sw = ctx.serviceWorkers()[0] ?? await ctx.waitForEvent('serviceworker')
assert.equal(new URL(sw.url()).host, EXT_ID, 'the extension id is stable')

const swCall = (type, payload = {}) => sw.evaluate(async ([t, p]) => { /* runs inside the service worker */ return null }, [type, payload])
async function popupFor(tabPage) {
  const tabId = tabPage ? await sw.evaluate(async (u) => (await chrome.tabs.query({})).find((t) => t.url === u)?.id, tabPage.url()) : undefined
  const p = await ctx.newPage()
  await p.goto(`chrome-extension://${EXT_ID}/popup.html` + (tabId ? `?tab=${tabId}` : ''))
  return p
}
async function ext(page, type, payload = {}) {
  return page.evaluate(async ([t, pl]) => chrome.runtime.sendMessage({ type: t, ...pl }), [type, payload])
}
const idOfName = (pop, name) => pop.evaluate(async (n) => (await chrome.runtime.sendMessage({ type: 'list', query: n, tabUrl: '' })).data.find((r) => r.name === n).id, name)
const siteUrl = (p, host = 'localhost') => `http://${host}:${site.port}${p}`
const tabOf = async (url) => { const p = await ctx.newPage(); watch(p, problems); await p.goto(url); return p }

await step('sign in through ClosedDoor and unlock with the master password', async () => {
  const p = await ctx.newPage()
  await p.goto(`chrome-extension://${EXT_ID}/popup.html`)
  await p.locator('#server').fill('not a url')
  await p.getByRole('button', { name: 'Continue' }).click()
  await p.getByRole('alert').filter({ hasText: 'full address' }).waitFor()
  await p.locator('#server').fill('http://example.com')
  await p.getByRole('button', { name: 'Continue' }).click()
  await p.getByRole('alert').filter({ hasText: 'https' }).waitFor()
  await p.locator('#server').fill(stack.url)
  await p.getByRole('button', { name: 'Continue' }).click()
  await p.getByRole('button', { name: 'Sign in with ClosedDoor' }).click()
  await p.locator('#pw').waitFor({ timeout: 30000 })
  await shot(p, 'ext-01-unlock')
  await p.locator('#pw').fill('wrong master password')
  await p.getByRole('button', { name: 'Unlock' }).click()
  await p.getByRole('alert').filter({ hasText: 'not correct' }).waitFor()
  await p.locator('#pw').fill(PW)
  await p.getByRole('button', { name: 'Unlock' }).click()
  await p.locator('#q').waitFor({ timeout: 30000 })
  await p.getByText('Test site').first().waitFor()
  await p.close()
})

await step('the server sees an extension device, and the browser holds ciphertext only', async () => {
  const dump = await sw.evaluate(async () => JSON.stringify({ l: await chrome.storage.local.get(null), s: await chrome.storage.session.get(null) }))
  const local = await sw.evaluate(async () => JSON.stringify(await chrome.storage.local.get(null)))
  for (const secret of ['S3cret!pass', 'ana@site.test', 'Test site', PW, 'GEZDGNBVGY3T']) assert.ok(!local.includes(secret), `${secret} must never be stored in chrome.storage.local`)
  assert.ok(JSON.parse(dump).s.uk, 'the unlock key lives in session storage')
  const devices = await ana.page.evaluate(async () => (await (await fetch('/api/v1/sessions')).json()).sessions.filter((s) => s.kind === 'ext').length)
  assert.equal(devices, 1)
})

await step('fill: the saved login is offered for its site and filled into the visible fields', async () => {
  const page = await tabOf(siteUrl('/hidden.html'))
  await page.evaluate(() => { window.__inputs = []; document.addEventListener('input', (e) => window.__inputs.push(e.target.id), true) })
  const pop = await popupFor(page)
  await pop.getByText('For this site').waitFor()
  await shot(pop, 'ext-02-popup-match')
  await pop.getByRole('button', { name: 'Fill' }).click()
  await until(async () => (await page.locator('#p').inputValue()) !== '', 'the password to be filled')
  assert.equal(await page.locator('#u').inputValue(), 'ana@site.test')
  assert.equal(await page.locator('#p').inputValue(), 'S3cret!pass-0001')
  // honeypots a phishing page could add to harvest a filled value stay empty
  for (const id of ['hp-u', 'hp-p', 'hp-o']) assert.equal(await page.locator('#' + id).inputValue(), '', id + ' must not be filled')
  assert.ok((await page.evaluate(() => window.__inputs)).includes('p'), 'frameworks listening for input events see the fill')
  await pop.close(); await page.close()
})

await step('phishing: a different host, a look-alike address or a hostile frame never gets the password', async () => {
  // same server, different host name: 127.0.0.1 is not localhost
  const other = await tabOf(siteUrl('/login.html', '127.0.0.1'))
  const pop = await popupFor(other)
  await pop.getByText('Test site').first().waitFor()
  assert.equal(await pop.getByText('For this site').count(), 0, 'not offered for another host')
  assert.equal(await pop.getByRole('button', { name: 'Fill', exact: true }).count(), 0)
  const id = await idOfName(pop, 'Test site')
  const tabId = await sw.evaluate(async (u) => (await chrome.tabs.query({})).find((t) => t.url === u)?.id, other.url())
  const forced = await ext(pop, 'fill', { id, tabId })
  assert.equal(forced.error.code, 'no_match', 'even a forced fill is refused by the service worker')
  assert.equal(await other.locator('#p').inputValue(), '')
  await pop.close(); await other.close()

  // a trusted login embedded in a hostile page (top frame does not match)
  site.setFrameTarget(siteUrl('/login.html', 'localhost'))
  const host = await tabOf(siteUrl('/frame-host.html', '127.0.0.1'))
  const pop2 = await popupFor(host)
  const tabId2 = await sw.evaluate(async (u) => (await chrome.tabs.query({})).find((t) => t.url === u)?.id, host.url())
  assert.equal((await ext(pop2, 'fill', { id, tabId: tabId2 })).error.code, 'no_match')
  assert.equal(await host.frameLocator('#fr').locator('#p').inputValue(), '', 'the embedded login stays empty')
  await pop2.close(); await host.close()

  // a hostile frame inside the trusted page: only the page's own form is filled
  site.setFrameTarget(siteUrl('/login.html', '127.0.0.1'))
  const top = await tabOf(siteUrl('/with-frame.html', 'localhost'))
  const pop3 = await popupFor(top)
  await pop3.getByRole('button', { name: 'Fill', exact: true }).click()
  await until(async () => (await top.locator('#p').inputValue()) !== '', 'the top form to be filled')
  assert.equal(await top.frameLocator('#fr').locator('#p').inputValue(), '', 'a frame from another host must not receive the password')
  assert.equal(await top.frameLocator('#fr').locator('#u').inputValue(), '')
  await pop3.close(); await top.close()
})

await step('keyboard-shortcut path: one match fills, none or several are refused', async () => {
  const page = await tabOf(siteUrl('/login.html'))
  const pop = await popupFor(page)
  const tabId = await sw.evaluate(async (u) => (await chrome.tabs.query({})).find((t) => t.url === u)?.id, page.url())
  const r = await ext(pop, 'fillBest', { tabId })
  assert.equal(r.ok, true)
  await until(async () => (await page.locator('#p').inputValue()) === 'S3cret!pass-0001', 'fillBest to fill')
  await addLogin('Second account', 'two@site.test', 'Another-pass-2222', `http://localhost:${site.port}/`)
  await ext(pop, 'sync')
  assert.equal((await ext(pop, 'fillBest', { tabId })).error.code, 'several')
  await pop.close(); await page.close()
})

await step('one-time code and username-only steps are filled too', async () => {
  const page = await tabOf(siteUrl('/otp.html'))
  const pop = await popupFor(page)
  const id = await idOfName(pop, 'Test site')
  const tabId = await sw.evaluate(async (u) => (await chrome.tabs.query({})).find((t) => t.url === u)?.id, page.url())
  assert.equal((await ext(pop, 'fill', { id, tabId })).ok, true)
  const { totpCode, parseTotp } = await import('../../server/internal/web/static/js/core/totp.js')
  const want = [await totpCode(parseTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')), await totpCode(parseTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'), Date.now() + 2000)]
  await until(async () => want.includes(await page.locator('#otp').inputValue()), 'the one-time code to be filled')
  await page.goto(siteUrl('/stepped.html'))
  assert.equal((await ext(pop, 'fill', { id, tabId })).ok, true)
  assert.equal(await page.locator('#u').inputValue(), 'ana@site.test')
  await pop.close(); await page.close()
})

await step('save bar: a new login is offered after submit, and Save stores it encrypted', async () => {
  const page = await tabOf(siteUrl('/spa.html'))
  await page.locator('#u').fill('fresh@site.test')
  await page.locator('#p').fill('Brand-new-pw-777')
  await page.locator('#go').click()
  await until(async () => (await page.title()) === 'submitted', 'the SPA submit')
  // the bar lives in a closed shadow root: reach its buttons with the keyboard, as a person could
  await until(async () => page.evaluate(() => !!document.querySelector('[data-thevault]')), 'the save bar')
  await shot(page, 'ext-03-save-bar')
  await page.keyboard.press('Tab') // focus was on the submit button: the bar's Save button is the next tab stop
  await page.keyboard.press('Enter')
  await until(async () => !(await page.evaluate(() => !!document.querySelector('[data-thevault]'))), 'the bar to close')
  const pop = await popupFor(null)
  await pop.locator('#q').fill('localhost')
  await pop.getByText('fresh@site.test').first().waitFor()
  // and the web app agrees (it decrypts what the extension encrypted)
  await ana.page.goto(stack.url + '/#/all'); await ana.page.reload()
  await ana.page.locator('#master').fill(PW); await ana.page.getByRole('button', { name: 'Unlock' }).click()
  await ana.page.locator('#search').fill('fresh@site.test')
  await until(async () => (await ana.page.locator('.items .item-row').count()) === 1, 'the saved item in the web app')
  await pop.close(); await page.close()
})

await step('save bar: a changed password for a known username is offered as an update', async () => {
  const page = await tabOf(siteUrl('/spa.html'))
  await page.locator('#u').fill('fresh@site.test')
  await page.locator('#p').fill('Changed-pw-888')
  await page.locator('#go').click()
  await until(async () => page.evaluate(() => !!document.querySelector('[data-thevault]')), 'the update bar')
  await page.keyboard.press('Tab')
  await page.keyboard.press('Enter')
  await until(async () => !(await page.evaluate(() => !!document.querySelector('[data-thevault]'))), 'the bar to close')
  await ana.page.reload()
  await ana.page.locator('#master').fill(PW); await ana.page.getByRole('button', { name: 'Unlock' }).click()
  await ana.page.locator('#search').fill('fresh@site.test')
  await ana.page.locator('.items .item-row').first().click()
  await ana.page.locator('.fld', { hasText: 'Password' }).first().getByRole('button', { name: /Show password/ }).click()
  assert.equal(await ana.page.locator('.fld', { hasText: 'Password' }).first().locator('.v').innerText(), 'Changed-pw-888')
  await page.close()
})

await step('"never for this site" is remembered', async () => {
  const page = await tabOf(siteUrl('/spa.html'))
  await page.locator('#u').fill('someone@else.test'); await page.locator('#p').fill('Whatever-pw-999'); await page.locator('#go').click()
  await until(async () => page.evaluate(() => !!document.querySelector('[data-thevault]')), 'the bar')
  for (let i = 0; i < 3; i++) await page.keyboard.press('Tab') // Save, Not now, Never for this site
  await page.keyboard.press('Enter')
  await until(async () => !(await page.evaluate(() => !!document.querySelector('[data-thevault]'))), 'the bar to close')
  const pop = await popupFor(null)
  assert.deepEqual((await ext(pop, 'neverList')).data, ['localhost'])
  await ext(pop, 'neverRemove', { host: 'localhost' })
  await pop.close(); await page.close()
})

await step('lock: nothing can be listed or filled until the master password is entered again', async () => {
  const page = await tabOf(siteUrl('/login.html'))
  const pop = await popupFor(page)
  await pop.getByRole('button', { name: 'Lock TheVault' }).click()
  await pop.locator('#pw').waitFor()
  const tabId = await sw.evaluate(async (u) => (await chrome.tabs.query({})).find((t) => t.url === u)?.id, page.url())
  assert.equal((await ext(pop, 'list', { query: '', tabUrl: '' })).error.code, 'locked')
  assert.equal((await ext(pop, 'fillBest', { tabId })).error.code, 'locked')
  assert.equal(await sw.evaluate(async () => (await chrome.storage.session.get('uk')).uk), undefined, 'the key is gone from memory')
  assert.equal(await page.locator('#p').inputValue(), '')
  await pop.close(); await page.close()
})

await step('offline: with the server down, the encrypted copy still unlocks and fills', async () => {
  const pop = await popupFor(null)
  await pop.locator('#pw').fill(PW)
  await pop.getByRole('button', { name: 'Unlock' }).click()
  await pop.locator('#q').waitFor({ timeout: 30000 })
  await pop.getByRole('button', { name: 'Lock TheVault' }).click()
  await pop.locator('#pw').waitFor()
  stack.child.kill() // the server goes away
  await new Promise((r) => setTimeout(r, 500))
  await pop.locator('#pw').fill('wrong master password')
  await pop.getByRole('button', { name: 'Unlock' }).click()
  await pop.getByRole('alert').filter({ hasText: 'not correct' }).waitFor()
  await pop.locator('#pw').fill(PW)
  await pop.getByRole('button', { name: 'Unlock' }).click()
  await pop.locator('#q').waitFor({ timeout: 30000 })
  await pop.getByText('Offline').waitFor()
  const page = await tabOf(siteUrl('/login.html'))
  const pop2 = await popupFor(page)
  await pop2.getByText('For this site').waitFor()
  await shot(pop2, 'ext-04-offline')
  await pop2.getByRole('button', { name: 'Fill', exact: true }).first().click()
  await until(async () => (await page.locator('#p').inputValue()) !== '', 'an offline fill')
  await pop.close(); await pop2.close(); await page.close()
})

await step('no problems were logged by the pages under test', async () => {
  const bad = problems.filter((p) => !/ERR_CONNECTION_REFUSED|Failed to fetch|net::ERR/.test(p))
  assert.deepEqual(bad, [])
})

await ctx.close()
await web.close()
await stack.stop().catch(() => {})
await site.close()
console.log(failed ? `\n${failed} FAILED` : '\nall steps passed')
fs.writeFileSync(OUT + '/ext-results.json', JSON.stringify(results, null, 1))
process.exit(failed ? 1 : 0)
