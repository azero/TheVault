// Sharing a space key with another user: ephemeral-static ECDH (P-256) -> HKDF -> AES-256-GCM, then an ECDSA signature
// by the sharer over everything that matters. The server stores these wraps but cannot open or forge them.
import { b64uEncode, b64uDecode, utf8, concat } from './b64.js'
import { VaultCryptoError, aesKey, hkdf, open, randomBytes, seal, subtle } from './crypto.js'
import { importEncPublic, importSigPublic } from './keys.js'

const ECDH = { name: 'ECDH', namedCurve: 'P-256' }
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' }

export const generateSpaceKey = () => randomBytes(32)

const ctx = (spaceId, keyVersion, recipientSub) => `thevault/v1/share|${spaceId}|${keyVersion}|${recipientSub}`
const sigInput = (spaceId, keyVersion, recipientSub, role, eph, ct) =>
  utf8(`thevault/v1/share-sig\n${spaceId}\n${keyVersion}\n${recipientSub}\n${role}\n${eph}\n${ct}`)

/** Wrap `spaceKeyRaw` for one recipient. `sharer` is the unlocked Keyring (signs) plus the sharer's sub. */
export async function wrapSpaceKey({ spaceId, keyVersion, role, recipientSub, recipientEncPub, sharerSub, keyring, spaceKeyRaw }) {
  const eph = await subtle.generateKey(ECDH, true, ['deriveBits'])
  const bits = await subtle.deriveBits({ name: 'ECDH', public: await importEncPublic(recipientEncPub) }, eph.privateKey, 256)
  const shared = new Uint8Array(bits)
  const info = ctx(spaceId, keyVersion, recipientSub)
  const key = await aesKey(await hkdf(shared, info))
  shared.fill(0)
  const ct = await seal(key, spaceKeyRaw, info)
  const ephPub = b64uEncode(new Uint8Array(await subtle.exportKey('raw', eph.publicKey)))
  const sig = b64uEncode(new Uint8Array(await subtle.sign(ECDSA_SIGN, keyring.sigPriv, sigInput(spaceId, keyVersion, recipientSub, role, ephPub, ct))))
  return { eph: ephPub, ct, sig, by: sharerSub }
}

/** Verify the sharer's signature, then open the space key. Throws VaultCryptoError if anything does not fit. */
export async function unwrapSpaceKey({ spaceId, keyVersion, role, mySub, keyring, wrap, sharerSigPub }) {
  const ok = await subtle.verify(ECDSA_SIGN, await importSigPublic(sharerSigPub), b64uDecode(wrap.sig),
    sigInput(spaceId, keyVersion, mySub, role, wrap.eph, wrap.ct)).catch(() => false)
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

export { concat }
