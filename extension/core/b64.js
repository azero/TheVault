// base64url (no padding) and small byte helpers. Strict on decode: a malformed value is an error, never "best effort".
const enc = new TextEncoder()
const dec = new TextDecoder('utf-8', { fatal: true })

export const utf8 = (s) => enc.encode(s)
export const fromUtf8 = (b) => dec.decode(b)

export function b64uEncode(bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const B64U = /^[A-Za-z0-9_-]*$/
export function b64uDecode(str) {
  if (typeof str !== 'string' || !B64U.test(str) || str.length % 4 === 1) throw new TypeError('invalid base64url')
  const s = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4)
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]
  return d === 0
}

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
