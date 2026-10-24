// Everything the web app needs to know about the browser extension: is it part of this build, does this browser run it, and
// should we nudge this person. The nudge is a convenience, so every failure here means "say nothing".
import { h, icon } from './dom.js'
import { get } from './api.js'
import { href } from './router.js'

const KEY = 'tv.extension-prompt'
const MIN_CHROME = 116

let info
/** `{ available, version, size, sha256, filename, prefilled }`, fetched once. */
export function extensionInfo() {
  info ??= fetch('/download/extension.json', { credentials: 'same-origin', cache: 'no-store' })
    .then((r) => (r.ok ? r.json() : { available: false }))
    .catch(() => ({ available: false }))
  return info
}

export const formatSize = (n) => (n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB')

/** Desktop Chromium (Chrome, Edge, Brave, Vivaldi, Opera) new enough for a Manifest V3 extension with offscreen documents. */
export function canRunExtension(nav = navigator) {
  const ua = nav.userAgent || ''
  const mobile = nav.userAgentData?.mobile ?? /Android|iPhone|iPad|Mobile/i.test(ua)
  const m = /Chrome\/(\d+)/.exec(ua)
  return !mobile && !!m && Number(m[1]) >= MIN_CHROME
}

/** Which browser the person is using, to point at the right extensions page. */
export async function browserKey(nav = navigator) {
  const ua = nav.userAgent || ''
  try { if (nav.brave && (await nav.brave.isBrave())) return 'brave' } catch { /* not Brave */ }
  if (/Edg\//.test(ua)) return 'edge'
  if (/Vivaldi\//.test(ua)) return 'vivaldi'
  if (/OPR\//.test(ua)) return 'opera'
  return /Chrome\//.test(ua) ? 'chrome' : ''
}

export const BROWSERS = [
  ['chrome', 'Google Chrome', 'chrome://extensions'],
  ['edge', 'Microsoft Edge', 'edge://extensions'],
  ['brave', 'Brave', 'brave://extensions'],
  ['vivaldi', 'Vivaldi', 'vivaldi://extensions'],
  ['opera', 'Opera', 'opera://extensions'],
]

const store = {
  get: () => { try { return localStorage.getItem(KEY) } catch { return null } },
  set: (v) => { try { localStorage.setItem(KEY, v) } catch { /* private window or blocked storage: it will simply show again */ } },
}
export const rememberExtensionPrompt = () => store.set('done')

let worth
/** Is there anything to offer this browser and this person? Asked once per page load. */
function worthOffering() {
  worth ??= (async () => {
    if (!canRunExtension() || !(await extensionInfo()).available) return false
    try { return !(await get('/sessions')).sessions.some((s) => s.kind === 'ext') } catch { return false }
  })()
  return worth
}
const shouldPrompt = async () => !store.get() && (await worthOffering())

/** A dismissible banner for the top of the item list, filled in when we know it is worth showing. */
export function extensionPromo() {
  const slot = h('div', { class: 'content', hidden: true })
  shouldPrompt().then((yes) => {
    if (!yes) return
    const close = () => { store.set('dismissed'); slot.remove() }
    slot.append(h('div', { class: 'alert alert-info ext-promo', role: 'region', 'aria-label': 'Browser extension' }, icon('puzzle'),
      h('div', { class: 'grow' }, h('strong', {}, 'Fill passwords right in your browser. '), 'The TheVault extension for Chrome, Edge and Brave fills a login only when you ask it to, and offers to save new ones.'),
      h('div', { class: 'cluster' },
        h('a', { class: 'btn btn-primary btn-sm', href: href('/settings/extension') }, 'Get the extension'),
        h('button', { class: 'btn btn-sm', type: 'button', on: { click: close } }, 'Not now'))))
    slot.hidden = false
  })
  return slot
}
