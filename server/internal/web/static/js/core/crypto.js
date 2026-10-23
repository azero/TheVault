// Primitives for TheVault, all through WebCrypto. Parameters are fixed by docs/crypto.md (format v1).
// Nothing in here touches the DOM or the network, so the web UI and the extension share it unchanged.
import { b64uEncode, b64uDecode, utf8, concat } from './b64.js'

export const FORMAT = 'thevault/v1'
export const KDF_NAME = 'pbkdf2-sha256'
export const DEFAULT_ITERATIONS = 1_000_000
export const MIN_ITERATIONS = 600_000 // OWASP's figure for PBKDF2-HMAC-SHA256; clients refuse anything lower from the server
export const MAX_ITERATIONS = 20_000_000 // a hostile server must not be able to freeze a client either

const subtle = globalThis.crypto.subtle

export class VaultCryptoError extends Error {
  constructor(msg) { super(msg); this.name = 'VaultCryptoError' }
}

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n))
}

/** Uniform integer in [0, max) by rejection sampling: no modulo bias. */
export function randomInt(max) {
  if (!Number.isInteger(max) || max < 1 || max > 2 ** 32) throw new RangeError('bad range')
  if (max === 1) return 0
  const limit = Math.floor(2 ** 32 / max) * max
  const buf = new Uint32Array(1)
  for (;;) {
    globalThis.crypto.getRandomValues(buf)
    if (buf[0] < limit) return buf[0] % max
  }
}

export function checkKdf({ kdf, iterations }, { minIterations = MIN_ITERATIONS } = {}) {
  if (kdf !== KDF_NAME) throw new VaultCryptoError('unsupported key derivation: ' + kdf)
  if (!Number.isInteger(iterations) || iterations < minIterations || iterations > MAX_ITERATIONS) {
    throw new VaultCryptoError('refusing key-derivation parameters outside the safe range')
  }
}

/** Master key: PBKDF2-HMAC-SHA256(NFKC(password), salt, iterations) -> 32 bytes. Never leaves the client. */
export async function deriveMasterKey(password, salt, iterations, opts) {
  checkKdf({ kdf: KDF_NAME, iterations }, opts)
  if (salt.length < 16) throw new VaultCryptoError('salt too short')
  const base = await subtle.importKey('raw', utf8(String(password).normalize('NFKC')), 'PBKDF2', false, ['deriveBits'])
  const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 256)
  return new Uint8Array(bits)
}

/** HKDF-SHA256 with an empty salt (the input is already uniformly random) and a purpose string as `info`. */
export async function hkdf(ikm, info, length = 32) {
  const k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(info) }, k, length * 8)
  return new Uint8Array(bits)
}

export function aesKey(raw, extractable = false) {
  if (raw.length !== 32) throw new VaultCryptoError('AES-256 key must be 32 bytes')
  return subtle.importKey('raw', raw, 'AES-GCM', extractable, ['encrypt', 'decrypt'])
}

/** Envelope: "1.<iv>.<ciphertext+tag>" (base64url). `aad` binds the ciphertext to its context. */
export async function seal(key, plaintext, aad) {
  const iv = randomBytes(12)
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(aad), tagLength: 128 }, key, plaintext))
  return '1.' + b64uEncode(iv) + '.' + b64uEncode(ct)
}

const ENVELOPE = /^1\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{22,})$/
export function isEnvelope(s) {
  return typeof s === 'string' && ENVELOPE.test(s)
}

export async function open(key, envelope, aad) {
  const m = typeof envelope === 'string' && ENVELOPE.exec(envelope)
  if (!m) throw new VaultCryptoError('malformed envelope')
  try {
    return new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv: b64uDecode(m[1]), additionalData: utf8(aad), tagLength: 128 }, key, b64uDecode(m[2])))
  } catch {
    // wrong key, wrong context or tampered data: deliberately indistinguishable
    throw new VaultCryptoError('decryption failed')
  }
}

export const sealJson = (key, obj, aad) => seal(key, utf8(JSON.stringify(obj)), aad)
export async function openJson(key, envelope, aad) {
  return JSON.parse(new TextDecoder().decode(await open(key, envelope, aad)))
}

export async function sha256(...parts) {
  return new Uint8Array(await subtle.digest('SHA-256', concat(...parts)))
}

export { subtle }
