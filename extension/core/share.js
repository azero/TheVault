// Sharing a space key with another user: ephemeral-static ECDH (P-256) -> HKDF -> AES-256-GCM, then an ECDSA signature
// by the sharer over everything that matters. The server stores these wraps but cannot open or forge them.
import { b64uEncode, b64uDecode, utf8, concat } from './b64.js'
import { VaultCryptoError, aesKey, hkdf, open, randomBytes, seal, subtle } from './crypto.js'
import { fingerprint, importEncPublic, importSigPublic } from './keys.js'

const ECDH = { name: 'ECDH', namedCurve: 'P-256' }
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' }

export const generateSpaceKey = () => randomBytes(32)

const ctx = (spaceId, keyVersion, recipientSub) => `thevault/v1/share|${spaceId}|${keyVersion}|${recipientSub}`
// The role is deliberately not signed: the server enforces roles, and every member holds the key anyway, so a signed
// role would only make a role change (or a server-side promotion after the owner's account is erased) break the wrap.
const sigInput = (spaceId, keyVersion, recipientSub, eph, ct) =>
  utf8(`thevault/v1/share-sig\n${spaceId}\n${keyVersion}\n${recipientSub}\n${eph}\n${ct}`)

/** Wrap `spaceKeyRaw` for one recipient. `sharer` is the unlocked Keyring (signs) plus the sharer's sub. */
export async function wrapSpaceKey({ spaceId, keyVersion, recipientSub, recipientEncPub, sharerSub, keyring, spaceKeyRaw }) {
  const eph = await subtle.generateKey(ECDH, true, ['deriveBits'])
  const bits = await subtle.deriveBits({ name: 'ECDH', public: await importEncPublic(recipientEncPub) }, eph.privateKey, 256)
  const shared = new Uint8Array(bits)
  const info = ctx(spaceId, keyVersion, recipientSub)
  const key = await aesKey(await hkdf(shared, info))
  shared.fill(0)
  const ct = await seal(key, spaceKeyRaw, info)
  const ephPub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', eph.publicKey)))
  const sig = b64uEncode(new Uint8Array(await subtle.sign(ECDSA_SIGN, keyring.sigPriv, sigInput(spaceId, keyVersion, recipientSub, ephPub, ct))))
  return { eph: ephPub, ct, sig, by: sharerSub }
}

/** Verify the sharer's signature, then open the space key. Throws VaultCryptoError if anything does not fit. */
export async function unwrapSpaceKey({ spaceId, keyVersion, mySub, keyring, wrap, sharerSigPub }) {
  const ok = await subtle.verify(ECDSA_SIGN, await importSigPublic(sharerSigPub), b64uDecode(wrap.sig),
    sigInput(spaceId, keyVersion, mySub, wrap.eph, wrap.ct)).catch(() => false)
  if (!ok) throw new VaultCryptoError('The share was not signed by the person it claims to come from.')
  const ephPub = await subtle.importKey('raw', b64uDecode(wrap.eph), ECDH, true, [])
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: ephPub }, keyring.encPriv, 256))
  const info = ctx(spaceId, keyVersion, mySub)
  const key = await aesKey(await hkdf(shared, info))
  shared.fill(0)
  const raw = await open(key, wrap.ct, info)
  if (raw.length !== 32) throw new VaultCryptoError('bad space key')
  return raw
}

/**
 * Which signing key may vouch for this space's wrap? Never one the server names on its own: the sharer's keys must match the
 * fingerprint we pinned the first time we saw them (trust on first use), and for our own wraps they are our own keys.
 * `pinned` is the fingerprint remembered for `space.wrap.by` (or undefined). Returns `{ sigPub, fp }`; `fp` is set for another
 * person's key and should be pinned by the caller once the wrap has verified.
 */
export async function resolveSharer({ space, mySub, keyring, pinned }) {
  const by = space.wrap.by
  if (by === mySub) return { sigPub: keyring.sigPub, fp: null }
  const encPub = space.wrap_by_enc_pub, sigPub = space.wrap_by_sig_pub
  if (!encPub || !sigPub) throw new VaultCryptoError('The keys of the person who shared this space are not available, so the share cannot be verified. Ask an owner to rotate the key.')
  const m = space.members.find((x) => x.sub === by)
  if (m && (m.enc_pub !== encPub || m.sig_pub !== sigPub)) throw new VaultCryptoError('The server sent two different key sets for the same sharer. Do not trust this space.')
  const fp = await fingerprint(encPub, sigPub)
  if (pinned && pinned !== fp) throw new VaultCryptoError('The sharer’s keys changed since you first saw them. Verify their fingerprint with them before trusting this space.')
  return { sigPub, fp: pinned ? null : fp }
}

export { concat }
