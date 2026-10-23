// CSV import (Chrome/Edge, Bitwarden, 1Password, LastPass, generic) and plaintext export. Pure functions.
import { newItem, normalizeItem, TYPES } from './item.js'

/** RFC 4180 parser: quoted fields, doubled quotes, embedded newlines, CRLF/LF, BOM. */
export function parseCsv(text) {
  const rows = []
  let row = [], field = '', q = false, i = 0
  if (text.charCodeAt(0) === 0xfeff) i = 1
  for (; i < text.length; i++) {
    const c = text[i]
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++ } else q = false } else field += c
    } else if (c === '"' && field === '') q = true
    else if (c === ',') { row.push(field); field = '' }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++
      row.push(field); field = ''
      if (row.length > 1 || row[0] !== '') rows.push(row)
      row = []
    } else field += c
  }
  if (q) throw new Error('The file ends inside a quoted value. It may be truncated.')
  row.push(field)
  if (row.length > 1 || row[0] !== '') rows.push(row)
  return rows
}

const col = (headers, ...names) => headers.findIndex((h) => names.includes(h.trim().toLowerCase()))

/** Returns {items, format, skipped}. Items are normalised and ready to encrypt (no ids yet). */
export function importCsv(text) {
  const rows = parseCsv(text)
  if (rows.length < 2) return { items: [], format: 'empty', skipped: 0 }
  const h = rows[0].map((x) => x.trim().toLowerCase())
  const idx = {
    name: col(h, 'name', 'title'),
    url: col(h, 'url', 'login_uri', 'website', 'web site', 'uri'),
    user: col(h, 'username', 'login_username', 'user', 'login'),
    pass: col(h, 'password', 'login_password'),
    notes: col(h, 'note', 'notes', 'extra'),
    totp: col(h, 'totp', 'login_totp', 'otpauth', 'one-time password'),
    folder: col(h, 'folder', 'grouping', 'group'),
    fav: col(h, 'favorite', 'fav'),
    type: col(h, 'type'),
  }
  if (idx.pass < 0 && idx.notes < 0) throw new Error('No password or notes column found. Is this a password export?')
  const format = h.includes('login_uri') ? 'Bitwarden' : h.includes('grouping') ? 'LastPass' : h.includes('otpauth') || h.includes('title') ? '1Password' : h.includes('note') ? 'Chrome / Edge' : 'Generic CSV'
  const items = []
  let skipped = 0
  const get = (r, i) => (i >= 0 ? unq((r[i] ?? '').trim()) : '')
  for (const r of rows.slice(1)) {
    const type = get(r, idx.type).toLowerCase()
    const isNote = type === 'note' || type === 'securenote' || (!get(r, idx.pass) && !get(r, idx.user) && !get(r, idx.url))
    const it = newItem(isNote ? 'note' : 'login')
    it.name = get(r, idx.name) || get(r, idx.url) || get(r, idx.user)
    if (!it.name && !get(r, idx.notes)) { skipped++; continue }
    it.notes = unq(idx.notes >= 0 ? r[idx.notes] ?? '' : '').replace(/\r\n/g, '\n')
    it.folder = get(r, idx.folder).replace(/^\(none\)$/i, '')
    it.fav = ['1', 'true', 'yes'].includes(get(r, idx.fav).toLowerCase())
    if (!isNote) {
      // Bitwarden puts several URIs in one cell separated by newlines
      const urls = get(r, idx.url).split(/\r?\n/).map((u) => u.trim()).filter(Boolean)
      it.urls = urls.map((url) => ({ url, match: 'host' }))
      it.data.username = get(r, idx.user)
      it.data.password = idx.pass >= 0 ? unq(r[idx.pass] ?? '') : ''
      it.data.totp = get(r, idx.totp)
    }
    items.push(normalizeItem(it))
  }
  return { items, format, skipped }
}

// Spreadsheets evaluate a cell that starts with = + - @ (or TAB/CR), quoted or not, and a member can share an item whose name
// or password is a formula that sends the neighbouring cells somewhere. A leading apostrophe makes it plain text; import
// strips it again, so a round trip is lossless.
const FORMULA = /^[=+\-@\t\r]/
const q = (v) => {
  let t = String(v ?? '')
  if (FORMULA.test(t)) t = "'" + t
  return '"' + t.replace(/"/g, '""') + '"'
}
const unq = (t) => (/^'[=+\-@\t\r]/.test(t) ? t.slice(1) : t)

/** Plaintext CSV (logins only: the format other managers import). Notes and other types go to the JSON export. */
export function exportCsv(items) {
  const head = 'folder,favorite,type,name,notes,login_uri,login_username,login_password,login_totp'
  const lines = items.filter((i) => i.type === 'login' || i.type === 'note').map((i) =>
    [i.folder, i.fav ? 1 : '', i.type === 'note' ? 'note' : 'login', i.name, i.notes, i.urls.map((u) => u.url).join('\n'),
      i.data.username ?? '', i.data.password ?? '', i.data.totp ?? ''].map(q).join(','))
  return [head, ...lines].join('\r\n') + '\r\n'
}

export const exportJson = (items) => JSON.stringify({ format: 'thevault-plain', v: 1, exported: new Date().toISOString(), items }, null, 2)

export function importJson(text) {
  const j = JSON.parse(text)
  if (j?.format !== 'thevault-plain' || !Array.isArray(j.items)) throw new Error('This is not a TheVault export.')
  return { items: j.items.map(normalizeItem).filter((i) => TYPES[i.type]), format: 'TheVault JSON', skipped: 0 }
}
