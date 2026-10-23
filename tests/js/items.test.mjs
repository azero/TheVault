import test from 'node:test'
import assert from 'node:assert/strict'
import { aesKey, randomBytes } from '../../server/internal/web/static/js/core/crypto.js'
import { createVault, Keyring } from '../../server/internal/web/static/js/core/keys.js'
import { applyHistory, decryptItem, encryptItem, matchesQuery, newId, newItem, normalizeItem, ID_RE, MAX_BLOB_CHARS } from '../../server/internal/web/static/js/core/item.js'
import { generateSpaceKey, resolveSharer, unwrapSpaceKey, wrapSpaceKey } from '../../server/internal/web/static/js/core/share.js'

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

test('space key sharing: round trip, wrong recipient, forged signature, replay', async () => {
  const alice = await unlock('alice-pass-1234'), bob = await unlock('bob-pass-1234'), mallory = await unlock('mallory-pass-123')
  const sk = generateSpaceKey()
  const base = { spaceId: 'spc1', keyVersion: 1, recipientSub: 'bob', recipientEncPub: bob.kr.encPub, sharerSub: 'alice', keyring: alice.kr, spaceKeyRaw: sk }
  const wrap = await wrapSpaceKey(base)
  const common = { spaceId: 'spc1', keyVersion: 1, mySub: 'bob', keyring: bob.kr, wrap, sharerSigPub: alice.kr.sigPub }
  assert.deepEqual(await unwrapSpaceKey(common), sk)
  await assert.rejects(unwrapSpaceKey({ ...common, keyring: mallory.kr }), /decryption failed|signed/, 'someone else cannot open it')
  await assert.rejects(unwrapSpaceKey({ ...common, keyVersion: 2 }), /not signed/)
  await assert.rejects(unwrapSpaceKey({ ...common, mySub: 'carol' }), /not signed/, 'wrap replayed to another user')
  await assert.rejects(unwrapSpaceKey({ ...common, sharerSigPub: mallory.kr.sigPub }), /not signed/, 'server substituting its own sharer key')
  const forged = await wrapSpaceKey({ ...base, keyring: mallory, sharerSub: 'alice' }).catch(() => null)
  if (forged) await assert.rejects(unwrapSpaceKey({ ...common, wrap: forged }), /not signed|decryption/)
  // tampered ciphertext
  const t = { ...wrap, ct: wrap.ct.slice(0, -2) + (wrap.ct.endsWith('AA') ? 'BB' : 'AA') }
  await assert.rejects(unwrapSpaceKey({ ...common, wrap: t }), /not signed/)
})

test('the sharer key must match the pin, and the server cannot name a signing key of its own', async () => {
  const alice = await unlock('alice-pass-1234'), bob = await unlock('bob-pass-1234'), mallory = await unlock('mallory-pass-123')
  const sk = generateSpaceKey(), evilKey = generateSpaceKey()
  const wrap = await wrapSpaceKey({ spaceId: 's1', keyVersion: 1, recipientSub: 'bob', recipientEncPub: bob.kr.encPub, sharerSub: 'alice', keyring: alice.kr, spaceKeyRaw: sk })
  const members = [{ sub: 'alice', enc_pub: alice.kr.encPub, sig_pub: alice.kr.sigPub }]
  const space = { id: 's1', wrap, members, wrap_by_enc_pub: alice.kr.encPub, wrap_by_sig_pub: alice.kr.sigPub }
  const first = await resolveSharer({ space, mySub: 'bob', keyring: bob.kr, pinned: undefined })
  assert.equal(first.sigPub, alice.kr.sigPub); assert.ok(first.fp, 'first contact: the caller pins')
  const again = await resolveSharer({ space, mySub: 'bob', keyring: bob.kr, pinned: first.fp })
  assert.equal(again.fp, null)
  // a malicious server: genuine keys in members[] (so a naive check passes) but its own signing key on the wrap
  const forgedWrap = await wrapSpaceKey({ spaceId: 's1', keyVersion: 1, recipientSub: 'bob', recipientEncPub: bob.kr.encPub, sharerSub: 'alice', keyring: mallory.kr, spaceKeyRaw: evilKey })
  const lying = { ...space, wrap: forgedWrap, wrap_by_enc_pub: mallory.kr.encPub, wrap_by_sig_pub: mallory.kr.sigPub }
  await assert.rejects(resolveSharer({ space: lying, mySub: 'bob', keyring: bob.kr, pinned: first.fp }), /changed|different key sets/)
  const halfLying = { ...space, wrap: forgedWrap, wrap_by_sig_pub: mallory.kr.sigPub }
  await assert.rejects(resolveSharer({ space: halfLying, mySub: 'bob', keyring: bob.kr, pinned: first.fp }), /different key sets|changed/)
  // whatever resolveSharer returned, the forged wrap does not verify against the pinned key
  await assert.rejects(unwrapSpaceKey({ spaceId: 's1', keyVersion: 1, mySub: 'bob', keyring: bob.kr, wrap: forgedWrap, sharerSigPub: first.sigPub }), /not signed/)
  // a sharer who left (not in members[]) stays verifiable through their retired keys
  const departed = { ...space, members: [] }
  assert.equal((await resolveSharer({ space: departed, mySub: 'bob', keyring: bob.kr, pinned: first.fp })).sigPub, alice.kr.sigPub)
  await assert.rejects(resolveSharer({ space: { ...departed, wrap_by_sig_pub: '' }, mySub: 'bob', keyring: bob.kr, pinned: first.fp }), /not available/)
  // our own wraps use our own key, whatever the server says
  const mine = await wrapSpaceKey({ spaceId: 's2', keyVersion: 1, recipientSub: 'bob', recipientEncPub: bob.kr.encPub, sharerSub: 'bob', keyring: bob.kr, spaceKeyRaw: sk })
  const own = await resolveSharer({ space: { id: 's2', wrap: mine, members: [], wrap_by_sig_pub: mallory.kr.sigPub }, mySub: 'bob', keyring: bob.kr })
  assert.equal(own.sigPub, bob.kr.sigPub)
})

test('public keys come from the private keys, not from the server', async () => {
  const { payload } = await createVault('alice-pass-1234', FAST)
  const other = await createVault('mallory-pass-123', FAST)
  const kdf = { kdf: payload.kdf, iterations: payload.iterations, salt: payload.salt }
  const ok = await Keyring.fromPassword('alice-pass-1234', kdf, payload, { minIterations: 1000 })
  assert.equal(ok.encPub, payload.enc_pub); assert.equal(ok.sigPub, payload.sig_pub)
  const swapped = { ...payload, enc_pub: other.payload.enc_pub, sig_pub: other.payload.sig_pub }
  await assert.rejects(Keyring.fromPassword('alice-pass-1234', kdf, swapped, { minIterations: 1000 }), /do not belong/)
  const noPub = { ...payload }; delete noPub.enc_pub; delete noPub.sig_pub
  const derived = await Keyring.fromPassword('alice-pass-1234', kdf, noPub, { minIterations: 1000 })
  assert.equal(derived.encPub, payload.enc_pub)
})
