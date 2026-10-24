import test from 'node:test'
import assert from 'node:assert/strict'

// A tiny chrome.* stand-in: just enough of storage, identity and fetch for the extension's sign-in code.
function installChrome({ nextUser }) {
  const area = () => {
    const m = new Map()
    return {
      m,
      get: async (k) => { const keys = Array.isArray(k) ? k : [k]; return Object.fromEntries(keys.filter((x) => m.has(x)).map((x) => [x, structuredClone(m.get(x))])) },
      set: async (o) => { for (const [k, v] of Object.entries(o)) m.set(k, structuredClone(v)) },
      remove: async (k) => { for (const x of Array.isArray(k) ? k : [k]) m.delete(x) },
    }
  }
  const local = area(), session = area()
  globalThis.chrome = {
    storage: { local, session },
    runtime: { getPlatformInfo: async () => ({ os: 'linux' }) },
    identity: {
      getRedirectURL: () => 'https://abc.chromiumapp.org/cb',
      launchWebAuthFlow: async ({ url }) => 'https://abc.chromiumapp.org/cb?code=c1&state=' + new URL(url).searchParams.get('state'),
    },
  }
  globalThis.fetch = async () => new Response(JSON.stringify({ token: 'vxs_' + nextUser().sub, user: nextUser() }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  return { local, session }
}

test('a different account signing in does not inherit the previous cache or unlock key', async () => {
  let user = { sub: 'a'.repeat(32), email: 'ana@example.com' }
  const { local, session } = installChrome({ nextUser: () => user })
  const { signIn } = await import('../../extension/lib/server.js')
  await local.set({ server: 'https://vault.example.com' })

  await signIn()
  assert.equal(local.m.get('cacheOwner'), user.sub)
  // ana unlocks and syncs: an encrypted cache and the unlock key now exist
  await local.set({ cache: { seq: 40, items: { x: { blob: 'ciphertext' } }, keys: { wrapped_uk: 'w' } } })
  await session.set({ uk: 'key', unlockedAt: 1, offline: true, prompts: { 1: {} } })

  // renewal for the same person keeps everything
  await signIn()
  assert.ok(local.m.get('cache'), 'renewal must keep the offline copy')
  assert.equal(session.m.get('uk'), 'key', 'renewal must keep the vault unlocked')

  // ClosedDoor now answers for somebody else (shared browser profile): nothing carries over
  user = { sub: 'b'.repeat(32), email: 'bob@example.com' }
  await signIn()
  assert.equal(local.m.get('cache'), undefined, "bob must not inherit ana's cache (nor sync from her position)")
  for (const k of ['uk', 'unlockedAt', 'offline', 'prompts']) assert.equal(session.m.has(k), false, k + ' survived the account switch')
  assert.equal(local.m.get('cacheOwner'), user.sub)
  assert.equal(local.m.get('user').sub, user.sub)
})

test('a cache written before owners were recorded is kept only for the account that was signed in', async () => {
  let user = { sub: 'a'.repeat(32), email: 'ana@example.com' }
  const { local } = installChrome({ nextUser: () => user })
  const { adoptAccount } = await import('../../extension/lib/server.js')
  await local.set({ user, cache: { seq: 1, items: {}, keys: {} } })
  await adoptAccount(user.sub)
  assert.ok(local.m.get('cache'))
  // signed out earlier (user removed), then somebody signs in: ownership cannot be shown, so the cache goes
  local.m.delete('cacheOwner'); local.m.delete('user')
  await adoptAccount('b'.repeat(32))
  assert.equal(local.m.get('cache'), undefined)
})
