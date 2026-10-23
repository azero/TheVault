import test from 'node:test'
import assert from 'node:assert/strict'
import { b64uDecode, b64uEncode } from '../../server/internal/web/static/js/core/b64.js'
import { checkKdf, open, seal, aesKey, randomBytes, randomInt, MIN_ITERATIONS, isEnvelope } from '../../server/internal/web/static/js/core/crypto.js'
import {
  Keyring, createVault, fingerprint, formatRecoveryKey, newRecovery, parseRecoveryKey, proofFor, recoverVault, recoveryProof, rewrapForNewPassword,
} from '../../server/internal/web/static/js/core/keys.js'

const FAST = { iterations: 1000, minIterations: 1000 }
const kdfOf = (p) => ({ kdf: p.kdf, iterations: p.iterations, salt: p.salt })

test('base64url round trips and rejects junk', () => {
  for (const n of [0, 1, 2, 3, 31, 32, 33, 1000]) {
    const b = randomBytes(n)
    assert.deepEqual(b64uDecode(b64uEncode(b)), b)
  }
  for (const bad of ['a', 'ab+c', 'ab/c', 'ab=c', 'a b c', 'x'.repeat(5)]) assert.throws(() => b64uDecode(bad))
})

test('envelope: round trip, wrong key, wrong aad, tamper, truncation', async () => {
  const key = await aesKey(randomBytes(32))
  const env = await seal(key, new TextEncoder().encode('hunter2'), 'ctx-a')
  assert.ok(isEnvelope(env))
  assert.equal(new TextDecoder().decode(await open(key, env, 'ctx-a')), 'hunter2')
  await assert.rejects(open(key, env, 'ctx-b'), /decryption failed/)
  await assert.rejects(open(await aesKey(randomBytes(32)), env, 'ctx-a'), /decryption failed/)
  const [v, iv, ct] = env.split('.')
  const flipped = ct.slice(0, 3) + (ct[3] === 'A' ? 'B' : 'A') + ct.slice(4)
  await assert.rejects(open(key, [v, iv, flipped].join('.'), 'ctx-a'), /decryption failed/)
  await assert.rejects(open(key, [v, iv, ct.slice(0, 10)].join('.'), 'ctx-a'), /malformed/)
  await assert.rejects(open(key, 'garbage', 'ctx-a'), /malformed/)
  assert.notEqual(await seal(key, new Uint8Array(1), 'x'), await seal(key, new Uint8Array(1), 'x'), 'fresh IV each time')
})

test('KDF parameters outside the safe range are refused (downgrade / freeze protection)', () => {
  assert.throws(() => checkKdf({ kdf: 'pbkdf2-sha256', iterations: 1 }), /safe range/)
  assert.throws(() => checkKdf({ kdf: 'pbkdf2-sha256', iterations: MIN_ITERATIONS - 1 }), /safe range/)
  assert.throws(() => checkKdf({ kdf: 'pbkdf2-sha256', iterations: 1e9 }), /safe range/)
  assert.throws(() => checkKdf({ kdf: 'md5', iterations: 1e6 }), /unsupported/)
  checkKdf({ kdf: 'pbkdf2-sha256', iterations: MIN_ITERATIONS })
})

test('randomInt is in range and roughly uniform', () => {
  const n = 7, counts = new Array(n).fill(0)
  for (let i = 0; i < 70000; i++) counts[randomInt(n)]++
  for (const c of counts) assert.ok(Math.abs(c - 10000) < 600, `bucket ${c}`)
  assert.throws(() => randomInt(0))
})

test('createVault -> unlock round trip; server data is ciphertext only', async () => {
  const { payload, recoveryKey } = await createVault('correct horse battery staple', FAST)
  const json = JSON.stringify(payload)
  assert.ok(!json.includes('correct horse'))
  for (const f of ['wrapped_uk', 'enc_priv', 'sig_priv']) assert.ok(isEnvelope(payload[f]), f)
  assert.ok(isEnvelope(payload.recovery.wrapped_uk))
  assert.match(recoveryKey, /^([0-9A-Z]{6}-){8}[0-9A-Z]{6}$/)
  assert.notEqual(payload.auth, payload.recovery.proof)

  const kr = await Keyring.fromPassword('correct horse battery staple', kdfOf(payload), payload, { minIterations: 1000 })
  assert.equal(kr.encPub, payload.enc_pub)
  assert.equal(kr.ukRaw.length, 32)
  await assert.rejects(Keyring.fromPassword('wrong password', kdfOf(payload), payload, { minIterations: 1000 }), /decryption failed/)
  // unicode normalisation: composed and decomposed forms are the same password
  const a = await createVault('café-pass-word', FAST)
  await Keyring.fromPassword('café-pass-word', kdfOf(a.payload), a.payload, { minIterations: 1000 })
})

test('the auth proof is deterministic per password+salt, differs per salt, and is not the encryption key', async () => {
  const { payload } = await createVault('pw-one-two-three', FAST)
  const p1 = await proofFor('pw-one-two-three', kdfOf(payload), { minIterations: 1000 })
  assert.equal(p1, payload.auth)
  assert.notEqual(await proofFor('pw-one-two-four', kdfOf(payload), { minIterations: 1000 }), p1)
  const other = { ...kdfOf(payload), salt: b64uEncode(randomBytes(32)) }
  assert.notEqual(await proofFor('pw-one-two-three', other, { minIterations: 1000 }), p1)
  // the proof alone cannot open the user key
  const k = await aesKey(b64uDecode(p1))
  await assert.rejects(open(k, payload.wrapped_uk, 'thevault/v1/uk'), /decryption failed/)
})

test('change master password keeps the user key; old password stops working', async () => {
  const { payload } = await createVault('old password 1', FAST)
  const kr = await Keyring.fromPassword('old password 1', kdfOf(payload), payload, { minIterations: 1000 })
  const req = await rewrapForNewPassword(kr, 'old password 1', kdfOf(payload), 'new password 2', FAST)
  assert.equal(req.auth_old, payload.auth)
  assert.notEqual(req.auth_new, payload.auth)
  const updated = { ...payload, wrapped_uk: req.wrapped_uk, salt: req.salt, iterations: req.iterations }
  const kr2 = await Keyring.fromPassword('new password 2', kdfOf(updated), updated, { minIterations: 1000 })
  assert.deepEqual(kr2.ukRaw, kr.ukRaw)
  await assert.rejects(Keyring.fromPassword('old password 1', kdfOf(updated), updated, { minIterations: 1000 }))
})

test('recovery key: format, typo detection, and a full recovery', async () => {
  const raw = randomBytes(32)
  const text = await formatRecoveryKey(raw)
  assert.deepEqual(await parseRecoveryKey(text), raw)
  assert.deepEqual(await parseRecoveryKey(text.toLowerCase().replace(/-/g, ' ')), raw, 'case and separators do not matter')
  const typo = text.slice(0, 2) + (text[2] === 'A' ? 'B' : 'A') + text.slice(3)
  await assert.rejects(parseRecoveryKey(typo), /check characters|invalid/)
  await assert.rejects(parseRecoveryKey(text.slice(0, -3)), /54 characters/)

  const { payload, recoveryKey } = await createVault('forgotten password', FAST)
  const kr = await Keyring.fromPassword('forgotten password', kdfOf(payload), payload, { minIterations: 1000 })
  const proof = await recoveryProof(recoveryKey)
  assert.equal(proof, payload.recovery.proof)
  const r = await recoverVault(recoveryKey, payload.recovery.wrapped_uk, payload, 'a brand new password', FAST)
  assert.deepEqual(r.keyring.ukRaw, kr.ukRaw)
  assert.equal(r.request.proof, proof)
  assert.notEqual(r.recoveryKey, recoveryKey, 'recovery rotates the recovery key too')
  const nk = await newRecovery(kr)
  assert.notEqual(nk.recovery.proof, payload.recovery.proof)
  // a different recovery key cannot open the user key
  const other = (await createVault('x'.repeat(12), FAST)).recoveryKey
  await assert.rejects(recoverVault(other, payload.recovery.wrapped_uk, payload, 'whatever password', FAST), /decryption failed/)
})

test('fingerprints are stable and differ per key pair', async () => {
  const a = await createVault('pw-aaaaaaaa', FAST), b = await createVault('pw-bbbbbbbb', FAST)
  const fa = await fingerprint(a.payload.enc_pub, a.payload.sig_pub)
  assert.match(fa, /^([0-9a-f]{4} ){9}[0-9a-f]{4}$/)
  assert.equal(fa, await fingerprint(a.payload.enc_pub, a.payload.sig_pub))
  assert.notEqual(fa, await fingerprint(b.payload.enc_pub, b.payload.sig_pub))
  assert.notEqual(fa, await fingerprint(a.payload.enc_pub, b.payload.sig_pub))
})

test('default parameters work and are at least the minimum', async () => {
  const { payload } = await createVault('default parameters pw')
  assert.ok(payload.iterations >= MIN_ITERATIONS)
  await Keyring.fromPassword('default parameters pw', kdfOf(payload), payload)
})
