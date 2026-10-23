// Password-protected export: its own PBKDF2 salt and password, AES-256-GCM, so a backup file is safe to store.
import { b64uEncode, b64uDecode } from './b64.js'
import { DEFAULT_ITERATIONS, KDF_NAME, aesKey, checkKdf, deriveMasterKey, hkdf, openJson, randomBytes, sealJson, VaultCryptoError } from './crypto.js'
import { normalizeItem } from './item.js'

const AAD = 'thevault/v1/export'

async function keyFor(password, kdf, opts) {
  const mk = await deriveMasterKey(password, b64uDecode(kdf.salt), kdf.iterations, opts)
  const k = await aesKey(await hkdf(mk, 'thevault/v1/export-enc'))
  mk.fill(0)
  return k
}

export async function exportEncrypted(items, password, { iterations = DEFAULT_ITERATIONS, minIterations } = {}) {
  const opts = minIterations ? { minIterations } : undefined
  const kdf = { kdf: KDF_NAME, iterations, salt: b64uEncode(randomBytes(32)) }
  const key = await keyFor(password, kdf, opts)
  return JSON.stringify({ format: 'thevault-export', v: 1, ...kdf, data: await sealJson(key, { items }, AAD) }, null, 2)
}

export async function importEncrypted(text, password, opts) {
  let j
  try { j = JSON.parse(text) } catch { throw new VaultCryptoError('This is not a TheVault export file.') }
  if (j?.format !== 'thevault-export' || j.v !== 1) throw new VaultCryptoError('This is not a TheVault export file.')
  checkKdf(j, opts)
  const key = await keyFor(password, j, opts)
  const body = await openJson(key, j.data, AAD)
  return { items: body.items.map(normalizeItem), format: 'TheVault encrypted export', skipped: 0 }
}
