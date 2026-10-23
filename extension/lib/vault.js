// The extension's view of the vault: an encrypted cache in storage.local, decrypted on demand with the key held in
// storage.session. The decrypted index lives only in the service worker's memory (which Chrome discards when idle).
import { b64uDecode, b64uEncode } from '../core/b64.js'
import { aesKey, open } from '../core/crypto.js'
import { Keyring, fingerprint } from '../core/keys.js'
import { decryptItem, spaceNameAad, PERSONAL } from '../core/item.js'
import { unwrapSpaceKey } from '../core/share.js'
import { api } from './server.js'
import { local, session } from './store.js'

let index = null // [{ id, vaultId, seq, item, writable }]

export const dropIndex = () => { index = null }

export async function getUnlockKey() {
  const b = await session.get('uk')
  return b ? b64uDecode(b) : null
}
export async function setUnlockKey(raw) { await session.set({ uk: b64uEncode(raw), unlockedAt: Date.now() }) }
export async function clearUnlockKey() { dropIndex(); await session.remove('uk') }
export const isUnlocked = async () => !!(await session.get('uk'))

export async function loadCache() {
  return (await local.get('cache')) ?? { seq: 0, keyVersion: 1, items: {}, spaces: [], keys: null }
}

/** Pull changes from the server into the encrypted cache. Nothing in here is decrypted. */
export async function sync(full = false) {
  let cache = full ? { seq: 0, keyVersion: 1, items: {}, spaces: [], keys: (await loadCache()).keys } : await loadCache()
  for (;;) {
    const res = await api('GET', '/sync?since=' + cache.seq)
    cache.keyVersion = res.key_version
    cache.spaces = res.spaces
    for (const it of res.items) {
      if (it.purged) delete cache.items[it.id]
      else cache.items[it.id] = it
    }
    cache.seq = res.seq
    if (!res.more) break
  }
  const spaceIds = new Set(cache.spaces.map((s) => s.id))
  for (const [id, it] of Object.entries(cache.items)) if (it.vault_id !== PERSONAL && !spaceIds.has(it.vault_id)) delete cache.items[id]
  cache.at = Date.now()
  await local.set({ cache })
  dropIndex()
  return cache
}

const trustKey = (sub) => 'trust:' + sub
async function checkTrust(mySub, by, members) {
  if (by === mySub) return
  const m = members.find((x) => x.sub === by)
  if (!m) throw new Error('The sharer is no longer a member.')
  const fp = await fingerprint(m.enc_pub, m.sig_pub)
  const t = (await local.get(trustKey(mySub))) ?? {}
  if (t[by] && t[by] !== fp) throw new Error('The sharer’s keys changed. Verify their fingerprint in the web app.')
  if (!t[by]) { t[by] = fp; await local.set({ [trustKey(mySub)]: t }) }
}

/** Decrypt everything the cache holds (login items only matter to the extension, but all types are listed for search). */
export async function getIndex() {
  if (index) return index
  const uk = await getUnlockKey()
  if (!uk) return null
  const cache = await loadCache()
  const mySub = (await local.get('user'))?.sub ?? ''
  if (!cache.keys) throw new Error('No vault data on this device yet. Sign in and unlock while online.')
  const ring = await Keyring.fromUserKey(uk, cache.keys)
  const spaceKeys = new Map()
  for (const s of cache.spaces) {
    try {
      await checkTrust(mySub, s.wrap.by, s.members)
      const raw = await unwrapSpaceKey({ spaceId: s.id, keyVersion: s.wrap_key_version, role: s.role, mySub, keyring: ring, wrap: s.wrap, sharerSigPub: s.wrap_by_sig_pub })
      const key = await aesKey(raw)
      await open(key, s.name_blob, spaceNameAad(s.id, s.key_version)) // proves the key and the version are right
      spaceKeys.set(s.id, { key, version: s.key_version, writable: ['owner', 'editor'].includes(s.role), name: s.role })
    } catch { /* a space we cannot open is simply not offered */ }
  }
  const out = []
  for (const it of Object.values(cache.items)) {
    if (it.deleted_at || it.purged) continue
    const k = it.vault_id === PERSONAL ? { key: ring.uk, version: cache.keyVersion, writable: true } : spaceKeys.get(it.vault_id)
    if (!k || k.version !== it.key_version) continue
    try {
      out.push({ id: it.id, vaultId: it.vault_id, seq: it.seq, writable: k.writable, item: await decryptItem(k.key, { vaultId: it.vault_id, itemId: it.id, keyVersion: it.key_version }, it.blob) })
    } catch { /* undecryptable: skip */ }
  }
  ring.wipe()
  index = out
  return out
}

/** Personal-vault write helper (save a captured login). Returns the new cache entry's seq. */
export async function putPersonalItem({ id, baseSeq, item, encrypt }) {
  const cache = await loadCache()
  const blob = await encrypt(cache.keyVersion)
  const res = await api('PUT', '/items/' + id, { vault_id: PERSONAL, base_seq: baseSeq, key_version: cache.keyVersion, blob })
  cache.items[id] = { id, vault_id: PERSONAL, seq: res.seq, blob, key_version: cache.keyVersion, created_at: res.created_at, updated_at: res.updated_at, deleted_at: 0 }
  await local.set({ cache })
  dropIndex()
  return res
}

export { PERSONAL }
