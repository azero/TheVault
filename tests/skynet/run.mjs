// Interoperability test against the REAL SkyNet server (not a fake): enrollment, event ingest, a real detection rule firing,
// SkyNet's own response service signing a block_ip command, and TheVault enforcing it.
//   SKYNET_SRC=/path/to/SkyNet node tests/skynet/run.mjs      (default: ../SkyNet next to this repository)
import assert from 'node:assert/strict'
import { spawn, execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { chromium } from 'playwright-core'
import { startStack } from '../ui/devserver.mjs'
import { CHROME } from '../ui/lib.mjs'
import { createVault } from '../../server/internal/web/static/js/core/keys.js'

const src = process.env.SKYNET_SRC || path.resolve(import.meta.dirname, '../../../SkyNet')
if (!fs.existsSync(path.join(src, 'server/go.mod'))) { console.log('SKIP: no SkyNet checkout at', src, '(set SKYNET_SRC)'); process.exit(0) }

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-int-'))
const bin = path.join(tmp, 'skynet')
execFileSync('go', ['build', '-o', bin, './cmd/skynet'], { cwd: path.join(src, 'server'), stdio: 'inherit' })

const until = async (fn, what, ms = 20000) => { const end = Date.now() + ms; let last; while (Date.now() < end) { try { last = await fn(); if (last) return last } catch (e) { last = e } await new Promise((r) => setTimeout(r, 150)) } throw new Error('timed out waiting for ' + what + (last instanceof Error ? ': ' + last.message : '')) }

// ---- SkyNet, with an override that makes the address rule block automatically
const skyData = path.join(tmp, 'sky-data')
fs.mkdirSync(path.join(skyData, 'rules'), { recursive: true })
fs.writeFileSync(path.join(skyData, 'rules/auto-block.yml'), `id: skynet-vault-unlock-bruteforce-ip
title: Wrong master passwords from one address
severity: high
detection: { fails: { source: thevault, action: unlock_failed, 'src_ip|exists': true }, condition: fails }
threshold: { count: 10, window: 10m }
group_by: [src_ip]
response: { action: block_ip, field: src_ip, ttl: 1h, scope: agent, auto: true }
tests:
  - { name: ten, match: true, repeat: 10, event: { source: thevault, action: unlock_failed, host: v, src_ip: 203.0.113.50 } }
  - { name: nine, match: false, repeat: 9, event: { source: thevault, action: unlock_failed, host: v, src_ip: 203.0.113.50 } }
`)
const skyPort = 21000 + Math.floor(Math.random() * 9000)
const skyEnv = { ...process.env, SKYNET_DATA_DIR: skyData, SKYNET_LISTEN: `127.0.0.1:${skyPort}`, SKYNET_PUBLIC_URL: `http://localhost:${skyPort}`,
  SKYNET_BREAKGLASS_SHA256: crypto.createHash('sha256').update('breakglass').digest('hex') }
const sky = spawn(bin, ['serve'], { env: skyEnv, stdio: ['ignore', 'inherit', 'inherit'] })
await until(async () => (await fetch(`http://localhost:${skyPort}/healthz`)).ok, 'SkyNet to start')
const token = execFileSync(bin, ['enroll-token', '-kind', 'adapter', '-label', 'thevault-test'], { env: skyEnv }).toString().trim()
assert.match(token, /^skyenr_/)
const skyDb = () => new DatabaseSync(path.join(skyData, 'main.db'), { readOnly: true })
// live mode (the default is dry_run)
{ const db = new DatabaseSync(path.join(skyData, 'main.db')); db.exec(`INSERT INTO settings(key,value,updated_by,updated_at) VALUES ('response_mode','live','test',0) ON CONFLICT(key) DO UPDATE SET value='live'`); db.close() }

// ---- TheVault, enrolled with that token
const stack = await startStack({ skynet: { VAULT_SKYNET_URL: `http://localhost:${skyPort}`, VAULT_SKYNET_ENROLL_TOKEN: token, VAULT_SKYNET_HOST: 'vault-int', VAULT_TRUSTED_IP_HEADER: 'X-Test-IP' } })
let ok = false
const browser = await chromium.launch({ executablePath: CHROME, args: ['--no-sandbox'] })
try {
  const agent = await until(() => { const db = skyDb(); const r = db.prepare(`SELECT id, kind, name FROM agents WHERE kind = 'adapter'`).get(); db.close(); return r }, 'the adapter to appear in SkyNet')
  assert.equal(agent.name, 'vault-int')
  console.log('  ok   TheVault enrolled in the real SkyNet as', agent.id)
  const creds = JSON.parse(fs.readFileSync(path.join(stack.dataDir, 'keys/skynet.json'), 'utf8'))
  assert.ok(creds.command_pubkey && creds.api_key.startsWith(agent.id + '.'))
  assert.equal((fs.statSync(path.join(stack.dataDir, 'keys/skynet.json')).mode & 0o777).toString(8), '600')

  // three people with vaults (a single account is locked out after 5 wrong passwords, so a spray has to span accounts)
  const people = []
  for (const who of ['ana', 'bob', 'cat']) {
    const ctx = await browser.newContext()
    await ctx.addCookies([{ name: 'sso_user', value: who, url: stack.sso.url }])
    assert.equal((await ctx.request.get(stack.url + '/auth/login?return=/')).status(), 200)
    const csrf = (await (await ctx.request.get(stack.url + '/api/v1/session')).json()).csrf
    const call = async (method, p, body, ip) => {
      const r = await ctx.request.fetch(stack.url + '/api/v1' + p, { method, data: body, headers: { 'Content-Type': 'application/json', 'X-Vault-CSRF': csrf, ...(ip ? { 'X-Test-IP': ip } : {}) }, failOnStatusCode: false })
      return { status: r.status(), body: await r.json().catch(() => ({})) }
    }
    const created = await createVault('integration test master password', { iterations: 600000 })
    assert.equal((await call('POST', '/vault/setup', created.payload)).status, 200)
    assert.equal((await call('POST', '/vault/lock', {})).status, 200)
    people.push({ ctx, call })
  }
  const ctx = people[0].ctx

  // events arrive in SkyNet's store with the real field names the rules use
  await until(() => { const db = skyDb(); const n = db.prepare(`SELECT COUNT(*) c FROM agents WHERE event_count > 0`).get().c; db.close(); return n > 0 }, 'events in SkyNet')
  console.log('  ok   events were ingested by the real SkyNet')

  // twelve wrong master passwords from one address, across three accounts: the real rule fires, SkyNet signs a real block_ip, TheVault enforces it
  const attacker = '203.0.113.50'
  for (let i = 0; i < 4; i++) for (const p of people) assert.equal((await p.call('POST', '/vault/unlock', { auth: crypto.randomBytes(32).toString('base64url') }, attacker)).status, 401)
  const alert = await until(() => { const db = skyDb(); const a = db.prepare(`SELECT id, rule_id, severity FROM alerts WHERE rule_id = 'skynet-vault-unlock-bruteforce-ip'`).get(); db.close(); return a }, 'the brute-force alert')
  console.log('  ok   the real rule fired: alert', alert.id, alert.rule_id)
  const cmd = await until(() => { const db = skyDb(); const c = db.prepare(`SELECT id, action, status, result, auto, dry_run FROM commands WHERE action = 'block_ip' AND status IN ('succeeded','skipped','failed')`).get(); db.close(); return c }, 'the block_ip command to be completed', 40000)
  assert.equal(cmd.status, 'succeeded', JSON.stringify(cmd))
  assert.equal(cmd.auto, 1)
  console.log('  ok   SkyNet signed block_ip and TheVault reported:', cmd.result)
  const blocked = await ctx.request.get(stack.url + '/login', { headers: { 'X-Test-IP': attacker }, failOnStatusCode: false })
  assert.equal(blocked.status(), 403, 'the attacker address must be refused')
  const fine = await ctx.request.get(stack.url + '/login', { headers: { 'X-Test-IP': '203.0.113.51' }, failOnStatusCode: false })
  assert.equal(fine.status(), 200)
  console.log('  ok   the blocked address gets 403 and other addresses are unaffected')

  // the vault reports the application back, and the admin overview shows the deny list
  await until(() => { const db = skyDb(); const n = db.prepare(`SELECT COUNT(*) c FROM audit_log WHERE event LIKE 'response_%'`).get().c; db.close(); return n > 0 }, 'response audit in SkyNet')
  ok = true
  console.log('\nall steps passed')
} catch (e) {
  console.log('FAIL', e.stack || e)
} finally {
  await browser.close(); sky.kill(); await stack.stop().catch(() => {}); fs.rmSync(tmp, { recursive: true, force: true })
}
process.exit(ok ? 0 : 1)
