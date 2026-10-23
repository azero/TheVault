// Starts the fake ClosedDoor and the real server binary for browser tests or manual poking.
//   node tests/ui/devserver.mjs            -> prints the URL; sign in by setting the sso_user cookie (ana|bob|cat) on the SSO origin
import { spawn, execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { startFakeSso } from './fake_sso.mjs'

const root = path.resolve(import.meta.dirname, '../..')

export async function startStack({ port = 0, extensionIds = '', skynet = null } = {}) {
  const sso = await startFakeSso()
  const bin = path.join(os.tmpdir(), 'thevault-test-bin')
  execFileSync('go', ['build', '-o', bin, './cmd/thevault'], { cwd: path.join(root, 'server'), stdio: 'inherit' })
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'thevault-data-'))
  const free = port || 20000 + Math.floor(Math.random() * 20000)
  const url = `http://localhost:${free}`
  const env = { ...process.env, VAULT_DATA_DIR: dataDir, VAULT_LISTEN: `127.0.0.1:${free}`, VAULT_PUBLIC_URL: url, VAULT_OIDC_ISSUER: sso.url, VAULT_OIDC_CLIENT_ID: sso.clientId, VAULT_OIDC_CLIENT_SECRET: sso.clientSecret, VAULT_EXTENSION_IDS: extensionIds, ...(skynet ?? {}) }
  const child = spawn(bin, ['serve'], { env, stdio: ['ignore', 'inherit', 'inherit'] })
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(url + '/healthz')).ok) break } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100))
  }
  return { url, sso, dataDir, child, stop: async () => { child.kill(); await sso.close(); fs.rmSync(dataDir, { recursive: true, force: true }) } }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const s = await startStack({ port: Number(process.env.PORT || 8444), extensionIds: process.env.VAULT_EXTENSION_IDS || '' })
  console.log(`TheVault: ${s.url}\nFake ClosedDoor: ${s.sso.url}\nSet cookie sso_user=ana|bob|cat on ${s.sso.url} then open ${s.url}`)
  process.on('SIGINT', async () => { await s.stop(); process.exit(0) })
}
