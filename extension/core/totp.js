// TOTP (RFC 6238) / HOTP (RFC 4226) with HMAC-SHA1/256/512 through WebCrypto.
import { VaultCryptoError, subtle } from './crypto.js'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }

export function base32Decode(text) {
  const s = String(text).toUpperCase().replace(/[\s=-]/g, '')
  if (!s) throw new VaultCryptoError('empty secret')
  let bits = 0, acc = 0
  const out = []
  for (const ch of s) {
    const v = ALPHABET.indexOf(ch)
    if (v < 0) throw new VaultCryptoError('The secret is not valid base32.')
    acc = (acc << 5) | v; bits += 5
    if (bits >= 8) { out.push((acc >>> (bits - 8)) & 255); bits -= 8; acc &= (1 << bits) - 1 }
  }
  return Uint8Array.from(out)
}

/** Accepts a bare base32 secret or an otpauth://totp/... URI. */
export function parseTotp(input) {
  const text = String(input ?? '').trim()
  let secret = text, digits = 6, period = 30, algorithm = 'SHA1'
  if (/^otpauth:\/\//i.test(text)) {
    const u = new URL(text)
    if (u.hostname.toLowerCase() !== 'totp') throw new VaultCryptoError('Only time-based (TOTP) codes are supported.')
    secret = u.searchParams.get('secret') ?? ''
    digits = Number(u.searchParams.get('digits') ?? 6)
    period = Number(u.searchParams.get('period') ?? 30)
    algorithm = (u.searchParams.get('algorithm') ?? 'SHA1').toUpperCase()
  }
  if (!HASHES[algorithm] || ![6, 7, 8].includes(digits) || !(period >= 5 && period <= 300)) throw new VaultCryptoError('Unsupported TOTP parameters.')
  return { key: base32Decode(secret), digits, period, algorithm }
}

export async function hotp({ key, digits, algorithm }, counter) {
  const msg = new Uint8Array(8)
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter))
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: HASHES[algorithm] }, false, ['sign'])
  const mac = new Uint8Array(await subtle.sign('HMAC', k, msg))
  const o = mac[mac.length - 1] & 15
  const n = ((mac[o] & 0x7f) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3]
  return String(n % 10 ** digits).padStart(digits, '0')
}

export const totpCode = (spec, nowMs = Date.now()) => hotp(spec, Math.floor(nowMs / 1000 / spec.period))
export const secondsRemaining = (spec, nowMs = Date.now()) => spec.period - (Math.floor(nowMs / 1000) % spec.period)
