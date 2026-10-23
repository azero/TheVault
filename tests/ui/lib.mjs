import { chromium } from 'playwright-core'
import fs from 'node:fs'
import path from 'node:path'

export const CHROME = process.env.CHROME_PATH || (fs.existsSync('/opt/pw-browsers/chromium-1194/chrome-linux/chrome') ? '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' : undefined)
export const OUT = path.resolve(import.meta.dirname, 'out')
fs.mkdirSync(OUT, { recursive: true })

export async function launch(extra = {}) {
  return chromium.launch({ executablePath: CHROME, args: ['--no-sandbox'], ...extra })
}

/** A browser context signed in to the fake SSO as `who`, with problem collectors attached to every page. */
export async function person(browser, stack, who, { viewport = { width: 1360, height: 860 }, colorScheme = 'light' } = {}) {
  const ctx = await browser.newContext({ viewport, colorScheme, acceptDownloads: true, permissions: ['clipboard-read', 'clipboard-write'] })
  await ctx.addCookies([{ name: 'sso_user', value: who, url: stack.sso.url }])
  const problems = []
  ctx.on('page', (p) => watch(p, problems))
  const page = await ctx.newPage()
  return { ctx, page, problems, who }
}

export function watch(page, problems) {
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message))
  page.on('console', (m) => { if (['error', 'warning'].includes(m.type()) && !/favicon|Failed to load resource.*(401|423|429|403|404|409|400)/.test(m.text())) problems.push(`console.${m.type()}: ${m.text()}`) })
  page.on('requestfailed', (r) => { if (!/favicon/.test(r.url())) problems.push('requestfailed: ' + r.url() + ' ' + r.failure()?.errorText) })
  page.on('request', (r) => { const u = new URL(r.url()); if (!['localhost', '127.0.0.1'].includes(u.hostname) && u.protocol.startsWith('http')) problems.push('external request: ' + r.url()) })
}

export async function shot(page, name) {
  const file = path.join(OUT, name + '.png')
  await page.screenshot({ path: file, fullPage: false, animations: 'disabled' })
  return file
}

export const PASSWORD = 'correct horse battery staple 42'

/** Sign in, create the vault (setup wizard) and land in the app. Returns the recovery key. */
export async function signInAndSetup(page, stack, password = PASSWORD) {
  await page.goto(stack.url + '/login')
  await page.getByRole('link', { name: 'Sign in with ClosedDoor' }).click()
  await page.waitForURL(stack.url + '/')
  await page.locator('#new-pw').fill(password)
  await page.locator('#new-pw2').fill(password)
  await page.getByRole('button', { name: 'Create my vault' }).click()
  const keyEl = page.locator('.recovery')
  await keyEl.waitFor({ timeout: 30000 })
  const key = (await keyEl.innerText()).trim().split(/\s+/).join('-')
  await page.locator('#confirm-last').fill(key.split('-').pop())
  await page.locator('#saved').check()
  await page.getByRole('button', { name: 'Finish' }).click()
  await page.locator('.topbar').waitFor()
  return key
}

export async function unlockWith(page, password = PASSWORD) {
  await page.locator('#master').fill(password)
  await page.getByRole('button', { name: 'Unlock' }).click()
}
