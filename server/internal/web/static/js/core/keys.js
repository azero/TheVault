// Key hierarchy (docs/crypto.md):
//   master password --PBKDF2--> MK --HKDF--> enc key (wraps the user key) + auth proof (what the server verifies)
//   user key (UK, random)  encrypts items and wraps the user's two key pairs
//   recovery key (random)  independently wraps UK, so a forgotten master password is not fatal
import { b64uEncode, b64uDecode, utf8, concat, toHex } from './b64.js'
import {
  DEFAULT_ITERATIONS, KDF_NAME, VaultCryptoError, aesKey, checkKdf, deriveMasterKey, hkdf, open, randomBytes, seal, sha256, subtle,
} from './crypto.js'

const AAD = {
  uk: 'thevault/v1/uk',
  ukRecovery: 'thevault/v1/uk-recovery',
  encPriv: 'thevault/v1/enc-priv',
  sigPriv: 'thevault/v1/sig-priv',
}
const ECDH = { name: 'ECDH', namedCurve: 'P-256' }
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }

/** From the master password and the KDF parameters: the key that wraps UK, and the proof sent to the server. */
export async function deriveFromPassword(password, { kdf, iterations, salt }, opts) {
  checkKdf({ kdf, iterations }, opts)
  const mk = await deriveMasterKey(password, b64uDecode(salt), iterations, opts)
  const [enc, auth] = await Promise.all([hkdf(mk, 'thevault/v1/enc'), hkdf(mk, 'thevault/v1/auth')])
  mk.fill(0)
  const out = { encKey: await aesKey(enc), auth: b64uEncode(auth) }
  enc.fill(0)
  return out
}

async function deriveFromRecovery(rawKey) {
  const [enc, auth] = await Promise.all([hkdf(rawKey, 'thevault/v1/recovery-enc'), hkdf(rawKey, 'thevault/v1/recovery-auth')])
  return { encKey: await aesKey(enc), proof: b64uEncode(auth) }
}

// ---- recovery key: 256 random bits shown as 52 Crockford base32 characters plus 2 check characters ----
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

function toBase32(bytes) {
  let bits = 0, acc = 0, out = ''
  for (const b of bytes) {
    acc = (acc << 8) | b; bits += 8
    while (bits >= 5) { out += CROCKFORD[(acc >>> (bits - 5)) & 31]; bits -= 5 }
    acc &= (1 << bits) - 1
  }
  if (bits > 0) out += CROCKFORD[(acc << (5 - bits)) & 31]
  return out
}

function fromBase32(s) {
  let bits = 0, acc = 0
  const out = []
  for (const ch of s) {
    const v = CROCKFORD.indexOf(ch)
    if (v < 0) throw new VaultCryptoError('invalid character in recovery key')
    acc = (acc << 5) | v; bits += 5
    if (bits >= 8) { out.push((acc >>> (bits - 8)) & 255); bits -= 8; acc &= (1 << bits) - 1 }
  }
  return Uint8Array.from(out)
}

async function recoveryCheck(raw) {
  const h = await sha256(utf8('thevault/v1/recovery-check'), raw)
  return CROCKFORD[h[0] & 31] + CROCKFORD[h[1] & 31]
}

export async function formatRecoveryKey(raw) {
  const s = toBase32(raw) + (await recoveryCheck(raw))
  return s.match(/.{1,6}/g).join('-')
}

export async function parseRecoveryKey(text) {
  const s = String(text).toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1')
  if (s.length !== 54) throw new VaultCryptoError('A recovery key has 54 characters. Check for missing characters.')
  const raw = fromBase32(s.slice(0, 52))
  if (raw.length !== 32 || (await recoveryCheck(raw)) !== s.slice(52)) throw new VaultCryptoError('The check characters do not match. Look for a typo.')
  return raw
}

// ---- key pairs: ECDH P-256 (receive shared space keys) and ECDSA P-256 (sign what we share) ----
async function exportPublic(key) {
  return b64uEncode(new Uint8Array(await subtle.exportKey('raw', key)))
}

export const importEncPublic = (b64) => subtle.importKey('raw', b64uDecode(b64), ECDH, true, [])
export const importSigPublic = (b64) => subtle.importKey('raw', b64uDecode(b64), ECDSA, true, ['verify'])

/** 20 bytes of SHA-256 over both public keys, as ten groups of four hex digits. Compare out of band. */
export async function fingerprint(encPubB64, sigPubB64) {
  const h = await sha256(utf8('thevault/v1/fp\0'), b64uDecode(encPubB64), b64uDecode(sigPubB64))
  return toHex(h.subarray(0, 20)).match(/.{4}/g).join(' ')
}

async function newKeyPairs(ukKey) {
  const [e, s] = await Promise.all([
    subtle.generateKey(ECDH, true, ['deriveBits']),
    subtle.generateKey(ECDSA, true, ['sign', 'verify']),
  ])
  const [encPriv, sigPriv] = await Promise.all([
    subtle.exportKey('pkcs8', e.privateKey).then((k) => seal(ukKey, new Uint8Array(k), AAD.encPriv)),
    subtle.exportKey('pkcs8', s.privateKey).then((k) => seal(ukKey, new Uint8Array(k), AAD.sigPriv)),
  ])
  return { enc_pub: await exportPublic(e.publicKey), sig_pub: await exportPublic(s.publicKey), enc_priv: encPriv, sig_priv: sigPriv }
}

/**
 * Everything a brand-new vault needs. `payload` goes to POST /api/v1/vault/setup (the server only ever sees
 * ciphertext and proofs); `recoveryKey` must be shown to the user once and is not stored anywhere.
 */
export async function createVault(password, { iterations = DEFAULT_ITERATIONS, minIterations } = {}) {
  const opts = minIterations ? { minIterations } : undefined
  const salt = b64uEncode(randomBytes(32))
  const kdf = { kdf: KDF_NAME, iterations, salt }
  const { encKey, auth } = await deriveFromPassword(password, kdf, opts)
  const ukRaw = randomBytes(32)
  const ukKey = await aesKey(ukRaw)
  const recoveryRaw = randomBytes(32)
  const rec = await deriveFromRecovery(recoveryRaw)
  const pairs = await newKeyPairs(ukKey)
  const payload = {
    ...kdf, auth, key_version: 1,
    wrapped_uk: await seal(encKey, ukRaw, AAD.uk),
    ...pairs,
    recovery: { proof: rec.proof, wrapped_uk: await seal(rec.encKey, ukRaw, AAD.ukRecovery) },
  }
  const recoveryKey = await formatRecoveryKey(recoveryRaw)
  recoveryRaw.fill(0)
  ukRaw.fill(0)
  return { payload, recoveryKey }
}

/** The unlocked state: the user key plus the private halves of the key pairs. Lives in memory only. */
export class Keyring {
  constructor({ ukRaw, uk, encPriv, sigPriv, encPub, sigPub }) {
    this.ukRaw = ukRaw; this.uk = uk; this.encPriv = encPriv; this.sigPriv = sigPriv; this.encPub = encPub; this.sigPub = sigPub
  }

  static async fromUserKey(ukRaw, keys) {
    const uk = await aesKey(ukRaw)
    const [encP8, sigP8] = await Promise.all([open(uk, keys.enc_priv, AAD.encPriv), open(uk, keys.sig_priv, AAD.sigPriv)])
    const [encPriv, sigPriv] = await Promise.all([
      subtle.importKey('pkcs8', encP8, ECDH, false, ['deriveBits']),
      subtle.importKey('pkcs8', sigP8, ECDSA, false, ['sign']),
    ])
    encP8.fill(0); sigP8.fill(0)
    return new Keyring({ ukRaw: Uint8Array.from(ukRaw), uk, encPriv, sigPriv, encPub: keys.enc_pub, sigPub: keys.sig_pub })
  }

  /** Unlock with the master password and the server's unlock response ({wrapped_uk, enc_pub, ...}). */
  static async fromPassword(password, kdf, unlockResponse, opts) {
    const { encKey } = await deriveFromPassword(password, kdf, opts)
    const ukRaw = await open(encKey, unlockResponse.wrapped_uk, AAD.uk)
    return Keyring.fromUserKey(ukRaw, unlockResponse)
  }

  fingerprint() { return fingerprint(this.encPub, this.sigPub) }

  /** Zero the raw key material. (CryptoKey objects are dropped with the keyring.) */
  wipe() { this.ukRaw.fill(0) }
}

/** The server-side proof for unlocking, without deriving a keyring (used to re-prompt for the password). */
export async function proofFor(password, kdf, opts) {
  return (await deriveFromPassword(password, kdf, opts)).auth
}

/** New master password, same user key. Returns what POST /api/v1/vault/password needs. */
export async function rewrapForNewPassword(keyring, oldPassword, oldKdf, newPassword, { iterations = DEFAULT_ITERATIONS, minIterations } = {}) {
  const opts = minIterations ? { minIterations } : undefined
  const auth_old = await proofFor(oldPassword, oldKdf, opts)
  const salt = b64uEncode(randomBytes(32))
  const kdf = { kdf: KDF_NAME, iterations, salt }
  const { encKey, auth } = await deriveFromPassword(newPassword, kdf, opts)
  return { auth_old, auth_new: auth, ...kdf, wrapped_uk: await seal(encKey, keyring.ukRaw, AAD.uk) }
}

/** A fresh recovery key for the same user key. The old one stops working once the server accepts this. */
export async function newRecovery(keyring) {
  const raw = randomBytes(32)
  const rec = await deriveFromRecovery(raw)
  const out = { recovery: { proof: rec.proof, wrapped_uk: await seal(rec.encKey, keyring.ukRaw, AAD.ukRecovery) } }
  const key = await formatRecoveryKey(raw)
  raw.fill(0)
  return { ...out, recoveryKey: key }
}

/** Step 1 of recovery: the proof the server checks before it releases the recovery-wrapped user key. */
export async function recoveryProof(recoveryKeyText) {
  const raw = await parseRecoveryKey(recoveryKeyText)
  const { proof } = await deriveFromRecovery(raw)
  raw.fill(0)
  return proof
}

/** Step 2: open the user key with the recovery key and re-wrap it under a new master password + new recovery key. */
export async function recoverVault(recoveryKeyText, recoveryWrappedUk, keys, newPassword, { iterations = DEFAULT_ITERATIONS, minIterations } = {}) {
  const opts = minIterations ? { minIterations } : undefined
  const raw = await parseRecoveryKey(recoveryKeyText)
  const old = await deriveFromRecovery(raw)
  raw.fill(0)
  const ukRaw = await open(old.encKey, recoveryWrappedUk, AAD.ukRecovery)
  const keyring = await Keyring.fromUserKey(ukRaw, keys)
  const salt = b64uEncode(randomBytes(32))
  const kdf = { kdf: KDF_NAME, iterations, salt }
  const { encKey, auth } = await deriveFromPassword(newPassword, kdf, opts)
  const fresh = await newRecovery(keyring)
  return {
    keyring, recoveryKey: fresh.recoveryKey,
    request: { proof: old.proof, auth_new: auth, ...kdf, wrapped_uk: await seal(encKey, ukRaw, AAD.uk), recovery: fresh.recovery },
  }
}

export { AAD as KEY_AAD, concat }
