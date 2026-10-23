// Items: the JSON that goes inside an encrypted blob, and the AAD that ties a blob to its id, vault and key version.
import { open, seal, openJson, sealJson } from './crypto.js'

export const PERSONAL = 'personal'
export const MAX_BLOB_CHARS = 262144 // mirrors the server limit

export const itemAad = (vaultId, itemId, keyVersion) => `thevault/v1/item|${vaultId}|${itemId}|${keyVersion}`
export const spaceNameAad = (spaceId, keyVersion) => `thevault/v1/space-name|${spaceId}|${keyVersion}`

/** Field specs drive the editor, the detail view, import and search. `secret` fields are masked until revealed. */
export const TYPES = {
  login: {
    label: 'Login', plural: 'Logins', icon: 'globe', urls: true,
    fields: [
      { key: 'username', label: 'Username', kind: 'text', autocomplete: 'off' },
      { key: 'password', label: 'Password', kind: 'secret', generator: true },
      { key: 'totp', label: 'One-time password (TOTP) secret', kind: 'totp' },
    ],
    main: 'password',
  },
  api_key: {
    label: 'API key', plural: 'API keys', icon: 'key', urls: true,
    fields: [
      { key: 'service', label: 'Service', kind: 'text' },
      { key: 'key', label: 'Key or token', kind: 'secret', generator: true },
      { key: 'secret', label: 'Secret (if the service issues a pair)', kind: 'secret' },
      { key: 'env', label: 'Environment', kind: 'text', placeholder: 'production, staging, ...' },
      { key: 'expires', label: 'Expires', kind: 'date' },
    ],
    main: 'key',
  },
  server: {
    label: 'Server', plural: 'Servers', icon: 'server', urls: false,
    fields: [
      { key: 'host', label: 'Host', kind: 'text' },
      { key: 'port', label: 'Port', kind: 'text' },
      { key: 'username', label: 'Username', kind: 'text' },
      { key: 'password', label: 'Password', kind: 'secret', generator: true },
      { key: 'privateKey', label: 'Private key', kind: 'multiline-secret' },
    ],
    main: 'password',
  },
  card: {
    label: 'Card', plural: 'Cards', icon: 'card', urls: false,
    fields: [
      { key: 'holder', label: 'Name on card', kind: 'text' },
      { key: 'number', label: 'Card number', kind: 'secret' },
      { key: 'expiry', label: 'Expiry (MM/YY)', kind: 'text' },
      { key: 'cvv', label: 'Security code', kind: 'secret' },
      { key: 'pin', label: 'PIN', kind: 'secret' },
    ],
    main: 'number',
  },
  note: {
    label: 'Secure note', plural: 'Secure notes', icon: 'note', urls: false,
    fields: [],
    main: null,
  },
}

export const MATCH_MODES = {
  host: 'Same host only',
  domain: 'Host and its subdomains',
  exact: 'Exact address (path prefix)',
  never: 'Never offer',
}

export function newItem(type = 'login') {
  if (!TYPES[type]) throw new RangeError('unknown item type')
  const now = Date.now()
  return { v: 1, type, name: '', fav: false, folder: '', tags: [], notes: '', urls: [], data: {}, custom: [], history: [], created: now, updated: now }
}

const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '')

/** Defensive normaliser for anything decrypted or imported: unknown keys dropped, types forced, lengths capped. */
export function normalizeItem(raw) {
  const type = TYPES[raw?.type] ? raw.type : 'note'
  const it = newItem(type)
  it.name = str(raw.name, 200)
  it.fav = raw.fav === true
  it.folder = str(raw.folder, 100)
  it.tags = Array.isArray(raw.tags) ? raw.tags.slice(0, 20).map((t) => str(t, 40)).filter(Boolean) : []
  it.notes = str(raw.notes, 20000)
  it.urls = Array.isArray(raw.urls)
    ? raw.urls.slice(0, 10).map((u) => ({ url: str(u?.url, 2000), match: MATCH_MODES[u?.match] ? u.match : 'host' })).filter((u) => u.url)
    : []
  for (const f of TYPES[type].fields) it.data[f.key] = str(raw.data?.[f.key], f.kind === 'multiline-secret' ? 20000 : 2000)
  it.custom = Array.isArray(raw.custom)
    ? raw.custom.slice(0, 30).map((c) => ({ label: str(c?.label, 100), value: str(c?.value, 2000), hidden: c?.hidden === true })).filter((c) => c.label || c.value)
    : []
  it.history = Array.isArray(raw.history) ? raw.history.slice(0, 10).map((h) => ({ value: str(h?.value, 2000), at: Number(h?.at) || 0 })) : []
  it.created = Number(raw.created) || it.created
  it.updated = Number(raw.updated) || it.updated
  return it
}

export async function encryptItem(key, { vaultId, itemId, keyVersion }, item) {
  const blob = await sealJson(key, { ...item, updated: Date.now() }, itemAad(vaultId, itemId, keyVersion))
  if (blob.length > MAX_BLOB_CHARS) throw new RangeError('This item is too large (limit 256 KB). Shorten the notes or key.')
  return blob
}

export async function decryptItem(key, { vaultId, itemId, keyVersion }, blob) {
  return normalizeItem(await openJson(key, blob, itemAad(vaultId, itemId, keyVersion)))
}

export const sealText = (key, text, aad) => seal(key, new TextEncoder().encode(text), aad)
export async function openText(key, blob, aad) {
  return new TextDecoder().decode(await open(key, blob, aad))
}

/** Move the old main secret into the history when it changes (keeps the last 10). */
export function applyHistory(prev, next) {
  const main = TYPES[next.type].main
  if (!prev || !main) return next
  const before = prev.data[main]
  if (before && before !== next.data[main]) {
    next.history = [{ value: before, at: Date.now() }, ...prev.history].slice(0, 10)
  } else {
    next.history = prev.history
  }
  return next
}

export function searchText(item) {
  const t = TYPES[item.type]
  const parts = [item.name, item.folder, item.tags.join(' '), item.urls.map((u) => u.url).join(' '), t.label]
  for (const f of t.fields) if (f.kind === 'text') parts.push(item.data[f.key])
  return parts.join('\n').toLowerCase()
}

export function matchesQuery(item, query) {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean)
  const hay = searchText(item)
  return terms.every((t) => hay.includes(t))
}

export const newId = () => {
  const b = globalThis.crypto.getRandomValues(new Uint8Array(16))
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}
export const ID_RE = /^[0-9a-f]{32}$/
