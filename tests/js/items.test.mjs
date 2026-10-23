import test from 'node:test'
import assert from 'node:assert/strict'
import { aesKey, randomBytes } from '../../server/internal/web/static/js/core/crypto.js'
import { createVault, Keyring } from '../../server/internal/web/static/js/core/keys.js'
import { applyHistory, decryptItem, encryptItem, matchesQuery, newId, newItem, normalizeItem, ID_RE, MAX_BLOB_CHARS } from '../../server/internal/web/static/js/core/item.js'
import { generateSpaceKey, unwrapSpaceKey, wrapSpaceKey } from '../../server/internal/web/static/js/core/share.js'

const FAST = { iterations: 1000, minIterations: 1000 }
const unlock = async (pw) => {
  const { payload } = await createVault(pw, FAST)
  const kr = await Keyring.fromPassword(pw, { kdf: payload.kdf, iterations: payload.iterations, salt: payload.salt }, payload, { minIterations: 1000 })
  return { kr, payload }
}

test('item round trip; a blob is bound to its id, vault and key version', async () => {
  const key = await aesKey(randomBytes(32))
  const it = newItem('login'); it.name = 'GitHub'; it.data.password = 'p@ss'
  const ctx = { vaultId: 'personal', itemId: newId(), keyVersion: 1 }
  const blob = await encryptItem(key, ctx, it)
  assert.ok(!blob.includes('GitHub'))
  assert.equal((await decryptItem(key, ctx, blob)).data.password, 'p@ss')
  await assert.rejects(decryptItem(key, { ...ctx, itemId: newId() }, blob), /decryption failed/, 'server swapping blobs between ids')
  await assert.rejects(decryptItem(key, { ...ctx, vaultId: 'other' }, blob), /decryption failed/, 'moving to another vault')
  await assert.rejects(decryptItem(key, { ...ctx, keyVersion: 2 }, blob), /decryption failed/, 'replaying an old key version')
})

test('oversized items are refused before upload', async () => {
  const key = await aesKey(randomBytes(32))
  const it = newItem('note'); it.notes = 'x'.repeat(20000)
  const ok = await encryptItem(key, { vaultId: 'personal', itemId: newId(), keyVersion: 1 }, it)
  assert.ok(ok.length < MAX_BLOB_CHARS)
  const big = newItem('server'); big.data.privateKey = 'k'.repeat(20000); big.custom = Array.from({ length: 30 }, () => ({ label: 'l', value: 'v'.repeat(2000), hidden: true }))
  await assert.rejects(encryptItem(key, { vaultId: 'personal', itemId: newId(), keyVersion: 1 }, { ...big, notes: 'n'.repeat(20000), junk: 'z'.repeat(300000) }), /too large/)
})

test('normalizeItem drops unknown keys, forces types and caps lengths', () => {
  const it = normalizeItem({ type: 'login', name: 5, fav: 'yes', urls: [{ url: 'a.com', match: 'bogus' }, { url: '' }], data: { username: 'u', evil: 'x', password: 3 }, custom: 'no', __proto__: { polluted: true } })
  assert.equal(it.name, ''); assert.equal(it.fav, false)
  assert.deepEqual(it.urls, [{ url: 'a.com', match: 'host' }])
  assert.equal(it.data.username, 'u'); assert.equal(it.data.evil, undefined); assert.equal(it.data.password, '')
  assert.deepEqual(it.custom, [])
  assert.equal(normalizeItem({ type: 'nonsense' }).type, 'note')
  assert.ok(ID_RE.test(newId()))
})

test('password history and search', () => {
  const a = newItem('login'); a.name = 'Router'; a.data.password = 'one'; a.urls = [{ url: 'https://192.168.0.1', match: 'host' }]
  const b = structuredClone(a); b.data.password = 'two'
  applyHistory(a, b)
  assert.equal(b.history[0].value, 'one')
  const c = structuredClone(b); applyHistory(b, c); assert.equal(c.history.length, 1, 'unchanged secret adds nothing')
  assert.ok(matchesQuery(a, 'router 192'))
  assert.ok(!matchesQuery(a, 'router nothing'))
})

test('space key sharing: round trip, wrong recipient, forged signature, altered role', async () => {
  const alice = await unlock('alice-pass-1234'), bob = await unlock('bob-pass-1234'), mallory = await unlock('mallory-pass-123')
  const sk = generateSpaceKey()
  const base = { spaceId: 'spc1', keyVersion: 1, role: 'editor', recipientSub: 'bob', recipientEncPub: bob.kr.encPub, sharerSub: 'alice', keyring: alice.kr, spaceKeyRaw: sk }
  const wrap = await wrapSpaceKey(base)
  const common = { spaceId: 'spc1', keyVersion: 1, role: 'editor', mySub: 'bob', keyring: bob.kr, wrap, sharerSigPub: alice.kr.sigPub }
  assert.deepEqual(await unwrapSpaceKey(common), sk)
  await assert.rejects(unwrapSpaceKey({ ...common, keyring: mallory.kr }), /decryption failed|signed/, 'someone else cannot open it')
  await assert.rejects(unwrapSpaceKey({ ...common, role: 'owner' }), /not signed/, 'server escalating the role')
  await assert.rejects(unwrapSpaceKey({ ...common, keyVersion: 2 }), /not signed/)
  await assert.rejects(unwrapSpaceKey({ ...common, mySub: 'carol' }), /not signed/, 'wrap replayed to another user')
  await assert.rejects(unwrapSpaceKey({ ...common, sharerSigPub: mallory.kr.sigPub }), /not signed/, 'server substituting its own sharer key')
  const forged = await wrapSpaceKey({ ...base, keyring: mallory, sharerSub: 'alice' }).catch(() => null)
  if (forged) await assert.rejects(unwrapSpaceKey({ ...common, wrap: forged }), /not signed|decryption/)
  // tampered ciphertext
  const t = { ...wrap, ct: wrap.ct.slice(0, -2) + (wrap.ct.endsWith('AA') ? 'BB' : 'AA') }
  await assert.rejects(unwrapSpaceKey({ ...common, wrap: t }), /not signed/)
})
