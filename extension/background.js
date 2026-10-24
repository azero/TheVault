// Service worker: owns the session, the unlock key, syncing, auto-lock, and every decision about filling.
// Content scripts and web pages never get secrets except through `fill`, which this file only sends after checking the
// frame's address against the item's saved website rules (core/urlmatch.js).
import { b64uEncode, utf8 } from './core/b64.js'
import { deriveFromPassword, Keyring } from './core/keys.js'
import { matchItems, matchScore, isFillableOrigin, parseUrl } from './core/urlmatch.js'
import { encryptItem, newId, newItem, normalizeItem, TYPES } from './core/item.js'
import { generatePassword } from './core/generator.js'
import { parseTotp, totpCode, secondsRemaining } from './core/totp.js'
import { api, signIn, getConfig, ExtError, normalizeServer } from './lib/server.js'
import { local, session, getPrefs, setPrefs } from './lib/store.js'
import { clearUnlockKey, dropIndex, getIndex, getUnlockKey, isUnlocked, loadCache, putPersonalItem, setUnlockKey, sync } from './lib/vault.js'

const EXT_URL = chrome.runtime.getURL('')
const SAVE_PROMPT_TTL = 120_000

// ---------- state ----------

async function status() {
  const { server, token, user } = await getConfig()
  const unlocked = await isUnlocked()
  const cache = await local.get('cache')
  return { configured: !!server, server, signedIn: !!token, user, unlocked, hasOfflineData: !!cache?.keys, syncedAt: cache?.at ?? 0, prefs: await getPrefs(), offline: !!(await session.get('offline')) }
}

async function touch() { await session.set({ lastActive: Date.now() }) }

/** The idle lock must not depend on a timer surviving: a service worker that keeps being restarted resets alarms. */
async function enforceIdle() {
  if (!(await isUnlocked())) return
  const last = (await session.get('lastActive')) ?? 0
  if (Date.now() - last > (await getPrefs()).idleMinutes * 60_000) await lockNow('idle')
}

async function liveIndex() {
  await enforceIdle()
  return getIndex()
}

async function lockNow(reason = 'manual', { remote = true } = {}) {
  await clearUnlockKey()
  await session.remove(['offline', 'prompts']) // a captured password must not outlive the lock

  await refreshBadges()
  if (remote) { try { await api('POST', '/vault/lock', {}) } catch { /* offline or signed out: the key is gone locally either way */ } }
}

// ---------- unlock ----------

async function finishUnlock(keyring, res) {
  await setUnlockKey(keyring.ukRaw)
  const cache = (await loadCache())
  if ((await getPrefs()).offlineCache) {
    cache.keys = { wrapped_uk: res.wrapped_uk, enc_pub: res.enc_pub, sig_pub: res.sig_pub, enc_priv: res.enc_priv, sig_priv: res.sig_priv, kdf: res.kdf, iterations: res.iterations, salt: res.salt }
  } else {
    cache.keys = { enc_pub: res.enc_pub, sig_pub: res.sig_pub, enc_priv: res.enc_priv, sig_priv: res.sig_priv }
  }
  await local.set({ cache })
  keyring.wipe()
}

async function unlock(password) {
  let pre
  try {
    pre = await api('GET', '/vault/prelogin')
  } catch (e) {
    if (e.code === 'network') return unlockOffline(password)
    throw e
  }
  const { encKey, auth } = await deriveFromPassword(password, pre)
  let res
  try {
    res = await api('POST', '/vault/unlock', { auth })
  } catch (e) {
    if (e.code === 'sso_expired') {
      await renewSignIn()
      res = await api('POST', '/vault/unlock', { auth })
    } else throw e
  }
  const ring = await Keyring.fromEncKey(encKey, res)
  await session.remove('offline')
  await finishUnlock(ring, res)
  await sync(true)
  await touch()
  await refreshBadges()
}

/** The ClosedDoor token behind our session expired: renew silently, or ask the person to sign in again. */
async function renewSignIn() {
  try { await signIn({ silent: true }) } catch (e) {
    if (e.code === 'interaction_required' || e.code === 'cancelled') await signIn({ silent: false })
    else throw e
  }
}

async function unlockOffline(password) {
  const cache = await loadCache()
  const k = cache.keys
  if (!k?.wrapped_uk) throw new ExtError('network', 'Cannot reach the vault server, and there is no offline copy on this device.')
  const ring = await Keyring.fromPassword(password, { kdf: k.kdf, iterations: k.iterations, salt: k.salt }, k).catch(() => { throw new ExtError('bad_password', 'That master password is not correct.') })
  await setUnlockKey(ring.ukRaw)
  await session.set({ offline: true })
  ring.wipe()
  await touch()
  await refreshBadges()
}

// ---------- listing ----------

function summary(e, tabUrl) {
  const it = e.item
  const host = parseUrl(it.urls[0]?.url)?.host ?? ''
  return { id: e.id, name: it.name, type: it.type, username: it.data.username || '', host, fav: it.fav, hasTotp: !!it.data.totp, shared: e.vaultId !== 'personal', match: !!tabUrl && it.urls.some((u) => matchScore(u, tabUrl) > 0) }
}

async function list({ query = '', tabUrl = '' }) {
  const idx = await liveIndex()
  if (!idx) throw new ExtError('locked', 'The vault is locked.')
  await touch()
  const q = query.toLowerCase().split(/\s+/).filter(Boolean)
  const hay = (e) => `${e.item.name} ${e.item.data.username ?? ''} ${e.item.urls.map((u) => u.url).join(' ')} ${e.item.folder} ${e.item.tags.join(' ')}`.toLowerCase()
  const matches = tabUrl && isFillableOrigin(tabUrl) ? new Set(matchItems(idx.map((e) => ({ ...e.item, id: e.id })), tabUrl).map((i) => i.id)) : new Set()
  const rows = idx.filter((e) => !q.length || q.every((t) => hay(e).includes(t)))
  const out = rows.map((e) => ({ ...summary(e, null), match: matches.has(e.id) }))
  out.sort((a, b) => (b.match - a.match) || (b.fav - a.fav) || a.name.localeCompare(b.name))
  return out.slice(0, 200)
}

async function entry(id) {
  const idx = await liveIndex()
  if (!idx) throw new ExtError('locked', 'The vault is locked.')
  const e = idx.find((x) => x.id === id)
  if (!e) throw new ExtError('not_found', 'That item is no longer available.')
  return e
}

async function field(id, name) {
  const e = await entry(id)
  await touch()
  if (name === 'totp') {
    const spec = parseTotp(e.item.data.totp)
    return { value: await totpCode(spec), remaining: secondsRemaining(spec), period: spec.period }
  }
  if (name === 'username' || name === 'password' || TYPES[e.item.type].fields.some((f) => f.key === name)) return { value: e.item.data[name] ?? '' }
  throw new ExtError('bad_request', 'Unknown field.')
}

// ---------- filling ----------

async function frameTargets(tabId, item) {
  const frames = (await chrome.webNavigation.getAllFrames({ tabId })) ?? []
  const top = frames.find((f) => f.parentFrameId === -1)
  const allowed = (url) => !!url && isFillableOrigin(url) && item.urls.some((r) => matchScore(r, url) > 0)
  // Both the page and the frame must match: a trusted login page embedded in a hostile site (or the reverse) is never filled.
  if (!top || !allowed(top.url)) return { top, targets: [] }
  return { top, targets: frames.filter((f) => f.errorOccurred !== true && allowed(f.url)) }
}

async function fillEntry(e, tabId) {
  const { top, targets } = await frameTargets(tabId, e.item)
  if (!targets.length) {
    throw new ExtError('no_match', top && !isFillableOrigin(top.url) ? 'TheVault only fills secure (https) pages.' : 'This login is not saved for this website.')
  }
  let otp = ''
  if (e.item.data.totp) { try { otp = await totpCode(parseTotp(e.item.data.totp)) } catch { /* bad secret: skip */ } }
  let filled = 0
  for (const f of targets) {
    try {
      const r = await chrome.tabs.sendMessage(tabId, { type: 'fill', username: e.item.data.username ?? '', password: e.item.data.password ?? '', otp }, { frameId: f.frameId, documentId: f.documentId })
      filled += r?.filled ?? 0
    } catch { /* frame without our content script */ }
  }
  if (!filled) throw new ExtError('no_fields', 'No login form was found on this page.')
  await touch()
  return { filled }
}

async function activeTab() {
  const [t] = await chrome.tabs.query({ active: true, lastFocusedWindow: true })
  return t
}

async function fillBest(tabId) {
  const idx = await liveIndex()
  if (!idx) throw new ExtError('locked', 'Unlock TheVault first (click the toolbar icon).')
  const tab = tabId ? await chrome.tabs.get(tabId) : await activeTab()
  if (!tab?.url) throw new ExtError('no_match', 'No page to fill.')
  const matches = matchItems(idx.map((e) => ({ ...e.item, id: e.id })), tab.url)
  if (matches.length === 0) throw new ExtError('no_match', 'No saved login for this website.')
  if (matches.length > 1) throw new ExtError('several', 'Several logins match. Choose one from the TheVault popup.')
  return fillEntry(idx.find((e) => e.id === matches[0].id), tab.id)
}

// ---------- saving captured logins ----------

async function hostNever() { return (await local.get('never')) ?? [] }

async function captured(sender, m) {
  if (!(await isUnlocked()) && !(await local.get('token'))) return
  const url = sender.url
  if (!isFillableOrigin(url) || typeof m.password !== 'string' || !m.password || m.password.length > 1000) return
  const username = String(m.username ?? '').slice(0, 300)
  const p = parseUrl(url)
  if ((await hostNever()).includes(p.host)) return
  // TheVault's own pages (unlock, password dialogs, the item editor) have password fields too, and the master password
  // must never reach this path
  const server = await local.get('server')
  if (server && p.origin === parseUrl(server)?.origin) return
  let kind = 'save', itemId = null, name = p.host
  const idx = await liveIndex().catch(() => null)
  if (idx) {
    const same = matchItems(idx.map((e) => ({ ...e.item, id: e.id })), url).filter((i) => (i.data.username ?? '') === username)
    if (same.some((i) => i.data.password === m.password)) return // already saved, nothing to offer
    if (same.length) { kind = 'update'; itemId = same[0].id; name = same[0].name }
  }
  const tabId = sender.tab.id
  const prompts = (await session.get('prompts')) ?? {}
  prompts[tabId] = { url: p.origin + '/', host: p.host, username, password: m.password, kind, itemId, name, at: Date.now() }
  await session.set({ prompts })
  setTimeout(() => chrome.tabs.sendMessage(tabId, { type: 'showSave' }, { frameId: 0 }).catch(() => {}), 1200)
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#1d4ed8' })
  chrome.action.setBadgeText({ tabId, text: '+' })
}

async function sweepPrompts() {
  const prompts = (await session.get('prompts')) ?? {}
  let changed = false
  for (const [id, p] of Object.entries(prompts)) if (Date.now() - p.at > SAVE_PROMPT_TTL) { delete prompts[id]; changed = true }
  if (changed) await session.set({ prompts })
}

async function promptFor(tabId) {
  const prompts = (await session.get('prompts')) ?? {}
  const p = prompts[tabId]
  if (!p) return null
  if (Date.now() - p.at > SAVE_PROMPT_TTL) { delete prompts[tabId]; await session.set({ prompts }); return null }
  return p
}

async function clearPrompt(tabId) {
  const prompts = (await session.get('prompts')) ?? {}
  delete prompts[tabId]
  await session.set({ prompts })
  chrome.action.setBadgeText({ tabId, text: '' })
  refreshBadge(tabId)
}

async function promptAction(tabId, action) {
  const p = await promptFor(tabId)
  if (!p) return { ok: false, message: 'The prompt expired.' }
  if (action === 'never') { await local.set({ never: [...new Set([...(await hostNever()), p.host])] }); await clearPrompt(tabId); return { ok: true } }
  if (action === 'dismiss') { await clearPrompt(tabId); return { ok: true } }
  if (!(await isUnlocked())) return { ok: false, locked: true, message: 'Unlock TheVault (toolbar icon), then save.' }
  if (await session.get('offline')) return { ok: false, message: 'You are offline. Saving needs a connection.' }
  const idx = await liveIndex()
  try {
    if (p.kind === 'update') {
      const e = idx.find((x) => x.id === p.itemId)
      if (!e || !e.writable || e.vaultId !== 'personal') return { ok: false, message: 'That login cannot be changed from here. Use the web app.' }
      const next = normalizeItem({ ...e.item, data: { ...e.item.data, password: p.password }, history: [{ value: e.item.data.password, at: Date.now() }, ...e.item.history] })
      await putPersonalItem({ id: e.id, baseSeq: e.seq, item: next, encrypt: async (kv) => encryptItem(await keyFor(), { vaultId: 'personal', itemId: e.id, keyVersion: kv }, next) })
    } else {
      const it = newItem('login')
      it.name = p.host
      it.data.username = p.username
      it.data.password = p.password
      it.urls = [{ url: p.url, match: 'host' }]
      const id = newId()
      await putPersonalItem({ id, baseSeq: 0, item: it, encrypt: async (kv) => encryptItem(await keyFor(), { vaultId: 'personal', itemId: id, keyVersion: kv }, it) })
    }
  } catch (e) {
    return { ok: false, message: e.message || 'Saving failed.' }
  }
  await clearPrompt(tabId)
  return { ok: true }
}

async function keyFor() {
  const uk = await getUnlockKey()
  return crypto.subtle.importKey('raw', uk, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

// ---------- badges, menus, alarms ----------

async function refreshBadge(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId)
    if (!tab.url || !(await isUnlocked())) return chrome.action.setBadgeText({ tabId, text: '' })
    if ((await promptFor(tabId))) return
    const idx = await liveIndex()
    const n = idx ? matchItems(idx.map((e) => ({ ...e.item, id: e.id })), tab.url).length : 0
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#1d4ed8' })
    chrome.action.setBadgeText({ tabId, text: n ? String(n) : '' })
  } catch { /* tab closed */ }
}
async function refreshBadges() {
  const tabs = await chrome.tabs.query({})
  await Promise.all(tabs.map((t) => refreshBadge(t.id)))
}

chrome.tabs.onUpdated.addListener(async (id, info) => {
  if (info.status !== 'complete') return
  refreshBadge(id)
  // the usual login is submit -> navigation: offer to save on the page that loads next
  if (await promptFor(id)) setTimeout(() => chrome.tabs.sendMessage(id, { type: 'showSave' }, { frameId: 0 }).catch(() => {}), 500)
})
chrome.tabs.onActivated.addListener(({ tabId }) => refreshBadge(tabId))
chrome.tabs.onRemoved.addListener(async (tabId) => { const p = (await session.get('prompts')) ?? {}; if (p[tabId]) { delete p[tabId]; await session.set({ prompts: p }) } })

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'fill', title: 'Fill login with TheVault', contexts: ['page', 'editable'] })
  chrome.contextMenus.create({ id: 'generate', title: 'Copy a generated password', contexts: ['editable'] })
})
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  try {
    if (info.menuItemId === 'fill') await fillBest(tab.id)
    if (info.menuItemId === 'generate') { await copyText(generatePassword({ length: 20 })) }
  } catch (e) { flash(tab?.id, e.message) }
})
chrome.commands.onCommand.addListener(async (cmd) => {
  if (cmd !== 'fill-login') return
  const tab = await activeTab()
  try { await fillBest(tab?.id) } catch (e) { flash(tab?.id, e.message); if (e.code === 'locked' || e.code === 'several') chrome.action.openPopup?.().catch(() => {}) }
})

function flash(tabId, text) {
  if (!tabId) return
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#b42318' })
  chrome.action.setBadgeText({ tabId, text: '!' })
  chrome.action.setTitle({ tabId, title: 'TheVault: ' + text })
  setTimeout(() => { chrome.action.setTitle({ tabId, title: 'TheVault' }); refreshBadge(tabId) }, 4000)
}

// auto-lock: idle time in the browser, screen lock, and a once-a-minute check against the person's idle setting
chrome.idle.setDetectionInterval(60)
chrome.idle.onStateChanged.addListener((s) => { if (s === 'locked') lockNow('screen locked') })
// create() with an existing name replaces the alarm and restarts its period, so doing it on every worker start would
// push the tick back each time the worker is woken
chrome.alarms.get('tick').then((a) => { if (!a) chrome.alarms.create('tick', { periodInMinutes: 1 }) })
enforceIdle()
chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === 'tick') {
    await sweepPrompts()
    if (!(await isUnlocked())) return
    await enforceIdle()
    if (!(await isUnlocked())) return
    if (Date.now() - (await session.get('pinged') ?? 0) > 4 * 60_000 && !(await session.get('offline'))) { await session.set({ pinged: Date.now() }); api('POST', '/vault/ping', {}).catch(() => {}) }
  }
  if (a.name === 'clip') await clearClipboard()
})

// ---------- clipboard ----------

async function copyText(text) {
  await ensureOffscreen()
  await chrome.runtime.sendMessage({ target: 'offscreen', type: 'copy', text })
  const secs = (await getPrefs()).clipboardSeconds
  if (secs > 0) chrome.alarms.create('clip', { when: Date.now() + secs * 1000 })
}
async function clearClipboard() { await ensureOffscreen(); await chrome.runtime.sendMessage({ target: 'offscreen', type: 'copy', text: '' }) }
async function ensureOffscreen() {
  if (await chrome.offscreen.hasDocument?.()) return
  await chrome.offscreen.createDocument({ url: 'offscreen.html', reasons: ['CLIPBOARD'], justification: 'Copy a password and clear it again after a delay.' })
}

// ---------- why can't I sign in? ----------

/**
 * Tells a wrong address from an extension the server does not know yet from an outage, so the popup can say what to fix
 * instead of "sign-in was cancelled". Two anonymous requests: GET /api/v1/session (our API answers with a JSON error), then
 * /ext/auth with a deliberately bad challenge, whose refusal page names VAULT_EXTENSION_IDS only for an id the vault has not
 * been told about. Nothing is sent that identifies a person, and no sign-in is started.
 */
async function diagnose() {
  const { server } = await getConfig()
  const id = chrome.runtime.id
  if (!server) return { state: 'not_configured', id }
  const plain = { cache: 'no-store', credentials: 'omit' }
  try {
    const res = await fetch(server + '/api/v1/session', { ...plain, headers: { Accept: 'application/json' } })
    let body = null
    try { body = await res.json() } catch { /* not JSON */ }
    if (!body || typeof body.error !== 'string') return { state: 'not_vault', id }
    const q = new URLSearchParams({ redirect_uri: chrome.identity.getRedirectURL('cb'), code_challenge: 'x', code_challenge_method: 'S256', state: 'x' })
    const probe = await fetch(`${server}/ext/auth?${q}`, { ...plain, redirect: 'manual' })
    return { state: (await probe.text()).includes('VAULT_EXTENSION_IDS') ? 'not_registered' : 'ok', id }
  } catch {
    // Unreadable: either nothing answered, or something answered without allowing this extension (no CORS header).
    try { await fetch(server + '/healthz', { mode: 'no-cors', ...plain }); return { state: 'not_registered', id } } catch { return { state: 'unreachable', id } }
  }
}

// ---------- messages ----------

const fromExtensionPage = (s) => typeof s.url === 'string' && s.url.startsWith(EXT_URL) && !s.tab?.url?.startsWith('http')

const EXT_HANDLERS = {
  status: () => status(),
  configure: async (m) => { const server = normalizeServer(m.server); const cur = await local.get('server'); if (cur && cur !== server) { await signOut(true) } await local.set({ server }); return status() },
  signIn: async () => { await signIn({ silent: false }); return status() },
  signOut: async () => { await signOut(false); return status() },
  unlock: async (m) => { await unlock(String(m.password ?? '')); return status() },
  lock: async () => { await lockNow('manual'); return status() },
  sync: async () => { await sync(false); await refreshBadges(); return status() },
  list: (m) => list(m),
  field: (m) => field(m.id, m.name),
  fill: async (m) => fillEntry(await entry(m.id), m.tabId),
  scheduleClear: async () => { const secs = (await getPrefs()).clipboardSeconds; if (secs > 0) chrome.alarms.create('clip', { when: Date.now() + secs * 1000 }); return { ok: true } },
  copyText: async (m) => { await copyText(String(m.text ?? '')); return { ok: true } },
  setPrefs: async (m) => { await setPrefs(m.prefs); if (m.prefs.idleMinutes) api('PUT', '/settings', { idle_lock_minutes: m.prefs.idleMinutes }).catch(() => {}); return status() },
  neverList: async () => hostNever(),
  neverRemove: async (m) => { await local.set({ never: (await hostNever()).filter((h) => h !== m.host) }); return hostNever() },
  fillBest: (m) => fillBest(m.tabId),
  diagnose: () => diagnose(),
}

const CONTENT_HANDLERS = {
  captured: (m, sender) => captured(sender, m),
  pending: async (m, sender) => { const p = await promptFor(sender.tab.id); return p ? { kind: p.kind, host: p.host, username: p.username, name: p.name, locked: !(await isUnlocked()) } : null },
  promptAction: (m, sender) => promptAction(sender.tab.id, m.action),
}

async function signOut(keepNothing) {
  try { if (await local.get('token')) await api('POST', '/session/logout', {}).catch(() => {}) } catch { /* ignore */ }
  await clearUnlockKey()
  await local.remove('token'); await local.remove('user')
  if (keepNothing) await local.remove('cache')
  await refreshBadges()
}

chrome.runtime.onMessage.addListener((m, sender, respond) => {
  if (m?.target === 'offscreen') return false
  const page = fromExtensionPage(sender)
  const handler = page ? EXT_HANDLERS[m?.type] : sender.tab ? CONTENT_HANDLERS[m?.type] : null
  if (!handler) { respond({ error: { code: 'forbidden', message: 'Not allowed.' } }); return false }
  Promise.resolve().then(() => handler(m, sender)).then((r) => respond({ ok: true, data: r })).catch((e) => respond({ error: { code: e.code || 'error', message: e.message || 'Failed.', retryAfter: e.retryAfter, body: e.body } }))
  return true
})
