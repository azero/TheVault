// The client-side vault: everything decrypted lives here, in memory, and nowhere else. The server only ever sees
// ciphertext; this module does the encrypting, decrypting, key handling and sharing through js/core.
import { api, get, post, put, del, setCsrf } from './api.js'
import { Keyring, deriveFromPassword, fingerprint, newRecovery, proofFor, recoverVault, recoveryProof, createVault, rewrapForNewPassword } from '../core/keys.js'
import { open, seal, sha256 } from '../core/crypto.js'
import { b64uEncode, utf8 } from '../core/b64.js'
import { PERSONAL, TYPES, applyHistory, decryptItem, encryptItem, matchesQuery, newId, newItem, normalizeItem, spaceNameAad } from '../core/item.js'
import { generateSpaceKey, unwrapSpaceKey, wrapSpaceKey } from '../core/share.js'
import { aesKey } from '../core/crypto.js'

const listeners = new Set()
export const subscribe = (fn) => { listeners.add(fn); return () => listeners.delete(fn) }
const notify = (what) => listeners.forEach((f) => f(what))

export class UserError extends Error {}

export const vault = {
  session: null,
  keyring: null,
  keyVersion: 1,
  kdf: null,
  items: new Map(), // id -> { id, vaultId, seq, keyVersion, deletedAt, createdAt, updatedAt, item | null, error }
  spaces: new Map(), // id -> { id, name, role, keyVersion, needsRotation, members, key, keyRaw, warning }
  seq: 0,
  get unlocked() { return !!this.keyring },
  get me() { return this.session?.user },
}

// ---------- session ----------

export async function loadSession() {
  const s = await get('/session')
  vault.session = s
  setCsrf(s.csrf)
  return s
}

export function isAdmin() { return vault.me?.role === 'admin' }

// ---------- unlock / lock ----------

export async function setupVaultFlow(password) {
  // Step 1 (before anything is sent): derive everything locally.
  return createVault(password)
}

/** Upload the new vault (ciphertext and proofs only) and continue unlocked: the server marks this session unlocked too. */
export async function finishSetup({ payload }, password) {
  await post('/vault/setup', payload)
  vault.keyring = await Keyring.fromPassword(password, payload, payload)
  vault.kdf = { kdf: payload.kdf, iterations: payload.iterations, salt: payload.salt }
  vault.keyVersion = 1
  await loadSession()
  await sync(true)
  notify('unlock')
}

/** Master password -> unlock on the server (proof) and locally (user key). */
export async function unlock(password) {
  const pre = await get('/vault/prelogin')
  const { encKey, auth } = await deriveFromPassword(password, pre)
  const res = await post('/vault/unlock', { auth })
  vault.keyring = await Keyring.fromEncKey(encKey, res)
  vault.kdf = { kdf: res.kdf, iterations: res.iterations, salt: res.salt }
  vault.keyVersion = res.key_version
  await loadSession()
  await sync(true)
  notify('unlock')
}

export function wipe() {
  proofCache = null
  vault.keyring?.wipe()
  for (const sp of vault.spaces.values()) sp.keyRaw?.fill(0)
  vault.keyring = null
  vault.items = new Map()
  vault.spaces = new Map()
  vault.seq = 0
}

export async function lock({ remote = true } = {}) {
  wipe()
  if (remote) { try { await post('/vault/lock') } catch { /* already locked or signed out */ } }
  try { await loadSession() } catch { /* signed out */ }
  notify('lock')
}

/** The server says the vault is locked (idle timeout, revoked): drop everything we hold. */
export function serverLocked() {
  if (!vault.keyring) return
  wipe()
  if (vault.session) vault.session.vault.state = 'locked'
  notify('lock')
}

export const ping = () => post('/vault/ping').catch(() => {})

// ---------- sync ----------

const trustKey = () => 'vault-trust:' + (vault.me?.sub ?? '')
function trusted() { try { return JSON.parse(localStorage.getItem(trustKey()) || '{}') } catch { return {} } }
function pin(sub, fp) { const t = trusted(); t[sub] = fp; try { localStorage.setItem(trustKey(), JSON.stringify(t)) } catch { /* ignore */ } }
export const pinnedFingerprint = (sub) => trusted()[sub]
export const pinFingerprint = pin

async function loadSpaces(list) {
  const next = new Map()
  for (const s of list) {
    const old = vault.spaces.get(s.id)
    const sp = { id: s.id, role: s.role, keyVersion: s.key_version, needsRotation: s.needs_rotation, members: s.members, createdBy: s.created_by, name: '(locked)', key: null, keyRaw: null, warning: '' }
    try {
      if (old?.key && old.keyVersion === s.key_version && old.keyRaw) {
        sp.key = old.key; sp.keyRaw = old.keyRaw
      } else {
        // TOFU: the first time we see a sharer's keys we remember their fingerprint; a change is refused, not shrugged off.
        const by = s.wrap.by
        if (by !== vault.me.sub) {
          const m = s.members.find((x) => x.sub === by)
          const fp = m ? await fingerprint(m.enc_pub, m.sig_pub) : null
          const pinned = pinnedFingerprint(by)
          if (!fp) throw new Error('The person who shared this space is no longer a member, so the share cannot be verified.')
          if (pinned && pinned !== fp) throw new Error('The sharer’s keys changed since you first saw them. Verify their fingerprint with them before trusting this space.')
          if (!pinned) pin(by, fp)
        }
        sp.keyRaw = await unwrapSpaceKey({ spaceId: s.id, keyVersion: s.wrap_key_version, role: s.role, mySub: vault.me.sub, keyring: vault.keyring, wrap: s.wrap, sharerSigPub: s.wrap_by_sig_pub })
        sp.key = await aesKey(sp.keyRaw)
      }
      const nameBytes = await open(sp.key, s.name_blob, spaceNameAad(s.id, s.key_version))
      sp.name = new TextDecoder().decode(nameBytes)
    } catch (e) {
      sp.warning = e.message || 'This space could not be opened.'
    }
    next.set(s.id, sp)
  }
  vault.spaces = next
}

function keyFor(vaultId) {
  if (vaultId === PERSONAL) return { key: vault.keyring.uk, keyVersion: vault.keyVersion }
  const sp = vault.spaces.get(vaultId)
  return sp?.key ? { key: sp.key, keyVersion: sp.keyVersion } : null
}

async function ingest(raw) {
  const prev = vault.items.get(raw.id)
  if (raw.purged) { vault.items.delete(raw.id); return }
  const entry = { id: raw.id, vaultId: raw.vault_id, seq: raw.seq, keyVersion: raw.key_version, deletedAt: raw.deleted_at || 0, createdAt: raw.created_at, updatedAt: raw.updated_at, item: null, error: '' }
  const k = keyFor(raw.vault_id)
  if (!k) entry.error = 'The key for this space is not available.'
  else if (k.keyVersion !== raw.key_version) entry.error = 'This item uses an older key and cannot be opened.'
  else {
    try { entry.item = await decryptItem(k.key, { vaultId: raw.vault_id, itemId: raw.id, keyVersion: raw.key_version }, raw.blob) } catch { entry.error = 'This item could not be decrypted.' }
  }
  if (prev && !entry.item && prev.item && !raw.blob) entry.item = prev.item // trash/restore responses carry no blob
  vault.items.set(raw.id, entry)
}

/** Pull changes from the server. `full` rebuilds everything (after unlock, or when memberships changed). */
export async function sync(full = false) {
  if (full) { vault.items = new Map(); vault.seq = 0 }
  let first = true
  for (;;) {
    const res = await get('/sync?since=' + vault.seq)
    if (first) { vault.keyVersion = res.key_version; await loadSpaces(res.spaces); first = false }
    for (const raw of res.items) await ingest(raw)
    vault.seq = res.seq
    if (!res.more) break
  }
  // memberships can shrink: forget items of spaces we are no longer in
  for (const [id, e] of vault.items) if (e.vaultId !== PERSONAL && !vault.spaces.has(e.vaultId)) vault.items.delete(id)
  notify('sync')
}

// ---------- reading ----------

export const entries = () => [...vault.items.values()]
export const live = () => entries().filter((e) => !e.deletedAt)
export const trash = () => entries().filter((e) => e.deletedAt)
export const getEntry = (id) => vault.items.get(id)
export const canWrite = (vaultId) => vaultId === PERSONAL || ['owner', 'editor'].includes(vault.spaces.get(vaultId)?.role)
export const spaceName = (id) => (id === PERSONAL ? 'Personal' : vault.spaces.get(id)?.name ?? 'Space')

export function folders() {
  const m = new Map()
  for (const e of live()) if (e.item?.folder) m.set(e.item.folder, (m.get(e.item.folder) ?? 0) + 1)
  return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]))
}

/** scope: {kind:'all'|'fav'|'type'|'folder'|'space'|'trash', value}, query string, sort. */
export function list(scope, query = '', sort = 'name') {
  let rows = scope.kind === 'trash' ? trash() : live()
  rows = rows.filter((e) => e.item)
  switch (scope.kind) {
    case 'fav': rows = rows.filter((e) => e.item.fav); break
    case 'type': rows = rows.filter((e) => e.item.type === scope.value); break
    case 'folder': rows = rows.filter((e) => e.item.folder === scope.value); break
    case 'space': rows = rows.filter((e) => e.vaultId === scope.value); break
    default: break
  }
  if (query) rows = rows.filter((e) => matchesQuery(e.item, query))
  const by = { name: (a, b) => a.item.name.localeCompare(b.item.name, undefined, { sensitivity: 'base' }), recent: (a, b) => b.item.updated - a.item.updated, created: (a, b) => b.item.created - a.item.created }
  return rows.sort(by[sort] || by.name)
}

export const counts = () => {
  const c = { all: 0, fav: 0, trash: trash().length, types: {}, spaces: {} }
  for (const e of live()) {
    c.all++
    if (e.item?.fav) c.fav++
    if (e.item) c.types[e.item.type] = (c.types[e.item.type] ?? 0) + 1
    if (e.vaultId !== PERSONAL) c.spaces[e.vaultId] = (c.spaces[e.vaultId] ?? 0) + 1
  }
  return c
}

// ---------- writing items ----------

function requireWrite(vaultId) {
  if (!canWrite(vaultId)) throw new UserError('You can only read items in this space.')
  const k = keyFor(vaultId)
  if (!k) throw new UserError('This space is not available.')
  return k
}

export async function saveItem({ id, vaultId, item }) {
  const existing = id ? vault.items.get(id) : null
  vaultId = existing ? existing.vaultId : vaultId || PERSONAL
  const k = requireWrite(vaultId)
  const itemId = id || newId()
  const next = normalizeItem(item)
  if (existing?.item) applyHistory(existing.item, next)
  next.created = existing?.item?.created ?? Date.now()
  const blob = await encryptItem(k.key, { vaultId, itemId, keyVersion: k.keyVersion }, next)
  const res = await put('/items/' + itemId, { vault_id: vaultId, base_seq: existing?.seq ?? 0, key_version: k.keyVersion, blob })
  const entry = { id: itemId, vaultId, seq: res.seq, keyVersion: k.keyVersion, deletedAt: 0, createdAt: res.created_at, updatedAt: res.updated_at, item: next, error: '' }
  vault.items.set(itemId, entry)
  notify('items')
  return entry
}

export async function moveItem(id, toVault) {
  const e = vault.items.get(id)
  if (!e?.item) throw new UserError('That item cannot be moved.')
  if (e.vaultId === toVault) return e
  requireWrite(e.vaultId)
  requireWrite(toVault)
  const copy = await saveItem({ id: null, vaultId: toVault, item: e.item })
  await del('/items/' + id + '?purge=1')
  vault.items.delete(id)
  notify('items')
  return copy
}

export async function trashItem(id) {
  const e = vault.items.get(id)
  requireWrite(e.vaultId)
  const res = await del('/items/' + id)
  Object.assign(e, { seq: res.seq, deletedAt: res.deleted_at || Math.floor(Date.now() / 1000) })
  notify('items')
}

export async function restoreItem(id) {
  const e = vault.items.get(id)
  requireWrite(e.vaultId)
  const res = await post('/items/' + id + '/restore')
  Object.assign(e, { seq: res.seq, deletedAt: 0 })
  notify('items')
}

export async function purgeItem(id) {
  const e = vault.items.get(id)
  requireWrite(e.vaultId)
  await del('/items/' + id + '?purge=1')
  vault.items.delete(id)
  notify('items')
}

export async function emptyTrash() {
  const rows = trash().filter((e) => canWrite(e.vaultId))
  for (const e of rows) await purgeItem(e.id)
  return rows.length
}

export async function toggleFavourite(id) {
  const e = vault.items.get(id)
  return saveItem({ id, vaultId: e.vaultId, item: { ...e.item, fav: !e.item.fav } })
}

export async function itemVersions(id) {
  const e = vault.items.get(id)
  const { versions } = await get('/items/' + id + '/versions')
  const k = keyFor(e.vaultId)
  const out = []
  for (const v of versions) {
    try { out.push({ savedAt: v.saved_at, item: await decryptItem(k.key, { vaultId: e.vaultId, itemId: id, keyVersion: v.key_version }, v.blob) }) } catch { /* undecryptable (older key) */ }
  }
  return out
}

// ---------- import / export ----------

export async function importItems(items, onProgress = () => {}) {
  const k = keyFor(PERSONAL)
  let done = 0
  for (let i = 0; i < items.length; i += 100) {
    const chunk = items.slice(i, i + 100)
    const payload = []
    const staged = []
    for (const it of chunk) {
      const id = newId()
      const next = normalizeItem(it)
      payload.push({ id, blob: await encryptItem(k.key, { vaultId: PERSONAL, itemId: id, keyVersion: k.keyVersion }, next) })
      staged.push({ id, item: next })
    }
    const res = await post('/items/import', { key_version: k.keyVersion, items: payload })
    res.items.forEach((r, idx) => {
      vault.items.set(r.id, { id: r.id, vaultId: PERSONAL, seq: r.seq, keyVersion: k.keyVersion, deletedAt: 0, createdAt: r.created_at, updatedAt: r.updated_at, item: staged[idx].item, error: '' })
    })
    done += chunk.length
    onProgress(done, items.length)
  }
  notify('items')
  return done
}

export function exportable(scope = 'all') {
  return live().filter((e) => e.item && (scope === 'all' || (scope === PERSONAL ? e.vaultId === PERSONAL : e.vaultId === scope))).map((e) => e.item)
}

export const reportClientEvent = (event, count) => post('/audit/client', { event, count }).catch(() => {})

// ---------- master password, recovery ----------

export async function changeMasterPassword(oldPw, newPw) {
  const req = await rewrapForNewPassword(vault.keyring, oldPw, vault.kdf, newPw)
  proofCache = null
  const res = await post('/vault/password', req)
  vault.kdf = { kdf: req.kdf, iterations: req.iterations, salt: req.salt }
  return res
}

// A just-verified proof is kept for a minute (as a digest of the password plus the proof) so that "confirm your password" and
// the action that follows do not each pay for a key derivation.
let proofCache = null
/** Asks the server to check the master password (throttled and audited like unlocking). Resolves with the proof. */
export async function verifyPassword(pw) {
  const digest = b64uEncode(await sha256(utf8(pw)))
  if (proofCache && proofCache.digest === digest && Date.now() - proofCache.at < 60000) return proofCache.proof
  const pre = await get('/vault/prelogin')
  const proof = await proofFor(pw, pre)
  try { await post('/vault/verify', { auth: proof }) } catch (e) {
    if (e.code === 'bad_password') throw new UserError('That master password is not correct.')
    if (e.code === 'locked_out') throw new UserError('Too many wrong passwords. Try again in a few minutes.')
    throw e
  }
  proofCache = { digest, proof, at: Date.now() }
  setTimeout(() => { if (proofCache && Date.now() - proofCache.at >= 60000) proofCache = null }, 61000)
  return proof
}

export async function rotateRecoveryKey(pw) {
  const auth = await verifyPassword(pw)
  const fresh = await newRecovery(vault.keyring)
  await post('/vault/recovery/rotate', { auth, recovery: fresh.recovery })
  return fresh.recoveryKey
}

export async function eraseOwnVault(pw) {
  await post('/vault/erase', { auth: await verifyPassword(pw) })
  wipe()
}

/** Recovery with the recovery key while locked. Returns the new recovery key to show. */
export async function recoverWithKey(recoveryKeyText, newPassword) {
  const proof = await recoveryProof(recoveryKeyText)
  const start = await post('/vault/recovery/start', { proof })
  const r = await recoverVault(recoveryKeyText, start.wrapped_uk, start, newPassword)
  await post('/vault/recovery/finish', r.request)
  vault.keyring = r.keyring
  return r.recoveryKey
}

/** After a successful recovery the session is unlocked on the server: bring the local state in line. */
export async function afterRecovery() {
  const pre = await get('/vault/prelogin')
  vault.kdf = { kdf: pre.kdf, iterations: pre.iterations, salt: pre.salt }
  vault.keyVersion = pre.key_version
  await loadSession()
  await sync(true)
  notify('unlock')
}

export async function ownFingerprint() { return vault.keyring.fingerprint() }

// ---------- spaces ----------

export async function createSpace(name) {
  const id = newId()
  const raw = generateSpaceKey()
  const key = await aesKey(raw)
  const me = vault.me
  const wrap = await wrapSpaceKey({ spaceId: id, keyVersion: 1, role: 'owner', recipientSub: me.sub, recipientEncPub: vault.keyring.encPub, sharerSub: me.sub, keyring: vault.keyring, spaceKeyRaw: raw })
  const name_blob = await seal(key, utf8(name), spaceNameAad(id, 1))
  await post('/spaces', { id, name_blob, wrap: { eph: wrap.eph, ct: wrap.ct, sig: wrap.sig } })
  await sync(true)
  return id
}

export async function renameSpace(id, name) {
  const sp = vault.spaces.get(id)
  await put('/spaces/' + id, { name_blob: await seal(sp.key, utf8(name), spaceNameAad(id, sp.keyVersion)) })
  sp.name = name
  notify('spaces')
}

export async function searchDirectory(q) { return (await get('/directory?q=' + encodeURIComponent(q))).users }

export async function addMember(spaceId, user, role) {
  const sp = vault.spaces.get(spaceId)
  const wrap = await wrapSpaceKey({ spaceId, keyVersion: sp.keyVersion, role, recipientSub: user.sub, recipientEncPub: user.enc_pub, sharerSub: vault.me.sub, keyring: vault.keyring, spaceKeyRaw: sp.keyRaw })
  await post(`/spaces/${spaceId}/members`, { sub: user.sub, role, key_version: sp.keyVersion, wrap: { eph: wrap.eph, ct: wrap.ct, sig: wrap.sig } })
  pin(user.sub, await fingerprint(user.enc_pub, user.sig_pub))
  await sync(true)
}

export async function setMemberRole(spaceId, sub, role) {
  await put(`/spaces/${spaceId}/members/${sub}`, { role })
  await sync(true)
}

export async function removeMember(spaceId, sub) {
  await del(`/spaces/${spaceId}/members/${sub}`)
  await sync(true)
}

export async function deleteSpace(id) { await del('/spaces/' + id); await sync(true) }

/** Swap the space key: re-encrypt every item, re-wrap for every remaining member. One atomic request. */
export async function rotateSpace(spaceId, onProgress = () => {}) {
  await sync(true) // be sure we hold the complete, current set
  const sp = vault.spaces.get(spaceId)
  if (!sp?.key) throw new UserError('This space is not available.')
  const rows = entries().filter((e) => e.vaultId === spaceId)
  if (rows.some((e) => !e.item)) throw new UserError('Some items in this space cannot be opened, so the key cannot be rotated safely. Ask another owner.')
  const version = sp.keyVersion + 1
  const raw = generateSpaceKey()
  const key = await aesKey(raw)
  const items = []
  for (const [i, e] of rows.entries()) {
    items.push({ id: e.id, base_seq: e.seq, blob: await encryptItem(key, { vaultId: spaceId, itemId: e.id, keyVersion: version }, e.item) })
    if (i % 25 === 0) onProgress(i, rows.length)
  }
  const members = []
  for (const m of sp.members) {
    const w = await wrapSpaceKey({ spaceId, keyVersion: version, role: m.role, recipientSub: m.sub, recipientEncPub: m.enc_pub, sharerSub: vault.me.sub, keyring: vault.keyring, spaceKeyRaw: raw })
    members.push({ sub: m.sub, wrap: { eph: w.eph, ct: w.ct, sig: w.sig } })
  }
  const name_blob = await seal(key, utf8(sp.name), spaceNameAad(spaceId, version))
  await post(`/spaces/${spaceId}/rotate`, { key_version: version, name_blob, items, members })
  await sync(true)
}

export const memberFingerprint = (m) => fingerprint(m.enc_pub, m.sig_pub)

// ---------- password health ----------

export async function healthReport() {
  const { estimateStrength } = await import('../core/strength.js')
  const rows = live().filter((e) => e.item)
  const weak = [], reused = [], old = [], insecure = [], expiring = [], noTotp = []
  const groups = new Map()
  const yearAgo = Date.now() - 365 * 86400 * 1000
  const soon = Date.now() + 30 * 86400 * 1000
  for (const e of rows) {
    const it = e.item
    const main = TYPES[it.type].main && it.data[TYPES[it.type].main]
    if (it.type === 'login' || it.type === 'server') {
      if (main) {
        if (estimateStrength(main).score <= 1) weak.push(e)
        const h = b64uEncode(await sha256(utf8(main)))
        groups.set(h, [...(groups.get(h) ?? []), e])
        if (it.updated < yearAgo) old.push(e)
      }
    }
    if (it.type === 'login' && it.urls.some((u) => /^http:\/\//i.test(u.url))) insecure.push(e)
    if (it.type === 'login' && !it.data.totp && it.urls.length) noTotp.push(e)
    if (it.type === 'api_key' && it.data.expires) {
      const t = Date.parse(it.data.expires)
      if (!Number.isNaN(t) && t < soon) expiring.push(e)
    }
  }
  for (const g of groups.values()) if (g.length > 1) reused.push(...g)
  return { total: rows.length, weak, reused, old, insecure, expiring, noTotp }
}

export { newItem, TYPES, PERSONAL }
