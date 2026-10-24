// The popup: sign in, unlock (the master password is only ever typed here), pick a login to fill or copy from.
import { h, icon, mount, toast, avatarClass, initials, debounce } from './ui.js'
import { generatePassword } from './core/generator.js'

const root = document.getElementById('root')
let tab = null
let state = null
let query = ''

async function call(type, payload = {}) {
  const r = await chrome.runtime.sendMessage({ type, ...payload })
  if (!r) throw new Error('The extension is not ready. Try again.')
  if (r.error) { const e = new Error(r.error.message); e.code = r.error.code; e.retryAfter = r.error.retryAfter; throw e }
  return r.data
}

const header = (extra) => h('div', { class: 'pop-head' }, h('img', { src: 'brand/logo-nav.webp', alt: 'TheVault' }), h('span', { class: 'spacer' }), extra)

async function refresh() {
  state = await call('status')
  // `?tab=<id>` lets tests (or a pinned popup page) target a specific tab; the popup normally acts on the active one
  const forced = Number(new URLSearchParams(location.search).get('tab'))
  tab = forced ? await chrome.tabs.get(forced) : (await chrome.tabs.query({ active: true, currentWindow: true }))[0]
  if (!state.configured) return viewConfigure()
  if (!state.signedIn) return viewSignIn()
  if (!state.unlocked) return viewUnlock()
  return viewList()
}

/** The downloaded package carries the address the web app was served from. It only fills the field: the person still confirms it. */
async function suggestedServer() {
  try {
    const r = await fetch(chrome.runtime.getURL('vault.json'))
    if (!r.ok) return ''
    const j = await r.json()
    return typeof j?.server === 'string' && j.server.length < 300 ? j.server : ''
  } catch { return '' }
}

async function viewConfigure() {
  const suggested = await suggestedServer()
  const input = h('input', { class: 'input', id: 'server', type: 'url', placeholder: 'https://vault.example.com', autocomplete: 'off', spellcheck: 'false', required: true, value: suggested })
  const msg = h('div', { class: 'pop-msg', role: 'alert' })
  const form = h('form', { class: 'pop-center', novalidate: true, on: { submit: async (e) => {
    e.preventDefault()
    try { await call('configure', { server: input.value }); refresh() } catch (err) { msg.textContent = err.message }
  } } },
  h('div', {}, h('h1', { class: 'pop-title' }, 'Welcome to TheVault'), h('p', { class: 'muted' }, 'Connect this extension to your company vault. Next you sign in with ClosedDoor, then unlock with your master password.')),
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'server' }, 'Your TheVault address'), input,
    h('span', { class: 'hint' }, suggested ? 'Filled in from where you downloaded this extension. Check that it is right, then continue.' : 'The address you open TheVault at in your browser. Ask your administrator if you do not know it.')), msg,
  h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, 'Continue'))
  mount(root, header(), form)
  input.focus()
}

/** What to do about a server the extension cannot use; null when it looks fine. */
function problemBox(d) {
  if (d.state === 'unreachable') return h('div', { class: 'alert alert-error', role: 'alert' }, icon('alert'), h('div', {}, h('strong', {}, 'Cannot reach this address. '), 'Check it for typing mistakes, and that you are on the company network or VPN if TheVault needs one.'))
  if (d.state === 'not_vault') return h('div', { class: 'alert alert-error', role: 'alert' }, icon('alert'), h('div', {}, h('strong', {}, 'This does not look like TheVault. '), 'Check the address you were given.'))
  if (d.state === 'not_registered') {
    const copyId = h('button', { class: 'btn btn-sm', type: 'button', on: { click: async () => { try { await navigator.clipboard.writeText(d.id); toast('Extension id copied') } catch { toast('Copying was blocked', 'error') } } } }, icon('copy', 'icon-sm'), 'Copy id')
    return h('div', { class: 'alert alert-warn', role: 'alert' }, icon('alert'), h('div', { class: 'stack-sm' }, h('div', {}, h('strong', {}, 'TheVault does not know this extension yet. '), 'Ask your administrator to add this extension id to ', h('code', {}, 'VAULT_EXTENSION_IDS'), '.'), h('code', { class: 'break' }, d.id), h('div', {}, copyId)))
  }
  return null
}

function viewSignIn() {
  const msg = h('div', { class: 'pop-msg', role: 'alert' })
  const problem = h('div', { class: 'pop-problem' })
  const btn = h('button', { class: 'btn btn-primary btn-block', type: 'button' }, 'Sign in with ClosedDoor')
  const check = async () => { try { const d = await call('diagnose'); mount(problem, problemBox(d)); return d } catch { return { state: 'ok' } } }
  btn.addEventListener('click', async () => {
    btn.disabled = true; msg.textContent = ''
    try { await call('signIn'); refresh() } catch (e) {
      btn.disabled = false
      // "cancelled" is what a closed or refused sign-in window looks like; say what is actually wrong when we can tell.
      const d = await check()
      msg.textContent = d.state === 'ok' ? e.message : ''
    }
  })
  mount(root, header(), h('div', { class: 'pop-center' }, h('div', {}, h('h1', { class: 'pop-title' }, 'Sign in'), h('p', { class: 'muted' }, 'Sign in with your company account. A window opens for ClosedDoor.')), btn, msg, problem,
    h('p', { class: 'small muted' }, state.server, ' · ', h('a', { href: '#', on: { click: (e) => { e.preventDefault(); chrome.runtime.openOptionsPage() } } }, 'Change'))))
  check()
}

function viewUnlock() {
  const pw = h('input', { class: 'input', id: 'pw', type: 'password', autocomplete: 'current-password', required: true })
  const msg = h('div', { class: 'pop-msg', role: 'alert' })
  const btn = h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, icon('unlock'), 'Unlock')
  const form = h('form', { class: 'pop-center', novalidate: true, on: { submit: async (e) => {
    e.preventDefault()
    if (!pw.value) return
    btn.disabled = true; btn.replaceChildren(h('span', { class: 'spin' }), 'Unlocking…'); msg.textContent = ''
    try { await call('unlock', { password: pw.value }); pw.value = ''; refresh() } catch (err) {
      btn.disabled = false; btn.replaceChildren(icon('unlock'), 'Unlock')
      msg.textContent = err.code === 'bad_password' ? 'That master password is not correct.' : err.code === 'locked_out' ? `Too many wrong passwords. Try again in ${Math.ceil((err.retryAfter || 60) / 60)} min.` : err.message
      pw.select()
      if (err.code === 'signed_out') refresh()
    }
  } } },
  h('div', { class: 'who' }, h('span', { class: `avatar ${avatarClass(state.user?.sub ?? '')}` }, initials(state.user?.name || state.user?.email)), h('div', {}, h('div', { class: 'name' }, state.user?.name || state.user?.email), h('div', { class: 'muted small' }, state.user?.email))),
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'pw' }, 'Master password'), pw), msg, btn,
  h('button', { class: 'btn btn-ghost btn-sm', type: 'button', on: { click: async () => { await call('signOut'); refresh() } } }, icon('logout', 'icon-sm'), 'Sign out'))
  mount(root, header(), form)
  pw.focus()
}

async function copy(text, label) {
  try { await navigator.clipboard.writeText(text); await call('scheduleClear'); toast(label + ' copied') } catch { toast('Copying was blocked', 'error') }
}

function viewList() {
  const search = h('input', { class: 'input', id: 'q', type: 'search', placeholder: 'Search', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Search your vault', value: query })
  const body = h('div', { class: 'pop-body' })
  const lockBtn = h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: 'Lock', 'aria-label': 'Lock TheVault', on: { click: async () => { await call('lock'); refresh() } } }, icon('lock'))
  const genBtn = h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: 'Generate a password', 'aria-label': 'Generate a password', on: { click: () => generate() } }, icon('wand'))
  const webBtn = h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: 'Open the web vault', 'aria-label': 'Open the web vault', on: { click: () => chrome.tabs.create({ url: state.server }) } }, icon('external'))
  const optBtn = h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: 'Settings', 'aria-label': 'Settings', on: { click: () => chrome.runtime.openOptionsPage() } }, icon('settings'))
  mount(root, h('div', { class: 'pop-head' }, h('img', { src: 'brand/logo-nav.webp', alt: 'TheVault' }), h('div', { class: 'spacer' }, search)), body,
    h('div', { class: 'pop-foot' }, genBtn, webBtn, optBtn, h('span', { class: 'spacer' }), state.offline ? h('span', { class: 'badge badge-warn' }, 'Offline') : null, lockBtn))
  const draw = async () => {
    let rows
    try { rows = await call('list', { query, tabUrl: tab?.url ?? '' }) } catch (e) { if (e.code === 'locked' || e.code === 'signed_out') return refresh(); mount(body, h('p', { class: 'alert alert-error' }, e.message)); return }
    const matches = rows.filter((r) => r.match), others = rows.filter((r) => !r.match)
    const row = (r) => h('li', { class: 'pop-row' + (r.match ? ' match' : '') },
      h('span', { class: `avatar avatar-sm sq ${avatarClass(r.name)}` }, initials(r.name).slice(0, 2)),
      h('div', { class: 'meta' }, h('div', { class: 'title truncate' }, r.name, r.shared ? h('span', { class: 'badge badge-gold' }, icon('users', 'icon-sm')) : null), h('div', { class: 'sub truncate' }, r.username || r.host)),
      h('div', { class: 'acts' },
        r.match ? h('button', { class: 'btn btn-primary btn-sm', type: 'button', on: { click: () => fill(r) } }, 'Fill') : null,
        r.username || r.type === 'login' ? h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: 'Copy username', 'aria-label': `Copy username for ${r.name}`, on: { click: () => field(r, 'username', 'Username') } }, icon('user')) : null,
        h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: 'Copy password', 'aria-label': `Copy password for ${r.name}`, on: { click: () => field(r, secretKey(r), 'Password') } }, icon('key')),
        r.hasTotp ? h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: 'Copy one-time code', 'aria-label': `Copy one-time code for ${r.name}`, on: { click: () => otp(r) } }, icon('clock')) : null))
    const parts = []
    if (matches.length) parts.push(h('div', { class: 'pop-section' }, 'For this site'), h('ul', { class: 'pop-list' }, matches.map(row)))
    parts.push(h('div', { class: 'pop-section' }, query ? 'Results' : 'All items'), others.length ? h('ul', { class: 'pop-list' }, others.map(row)) : query || rows.length ? h('p', { class: 'muted small' }, query ? 'Nothing matches.' : 'No other items.') : h('div', { class: 'stack-sm' }, h('p', { class: 'muted small' }, 'Your vault is empty. Add items in the web app, or log in to a site and TheVault will offer to save it.'), h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => chrome.tabs.create({ url: state.server }) } }, icon('external', 'icon-sm'), 'Open TheVault')))
    mount(body, ...parts)
  }
  search.addEventListener('input', debounce(() => { query = search.value; draw() }, 120))
  draw()
  search.focus()
}

const secretKey = (r) => ({ login: 'password', server: 'password', api_key: 'key', card: 'number' }[r.type] ?? 'password')

async function fill(r) {
  try { await call('fill', { id: r.id, tabId: tab.id }); window.close() } catch (e) { toast(e.message, 'error', 4500) }
}
async function field(r, name, label) {
  try { const { value } = await call('field', { id: r.id, name }); if (!value) { toast(`${label} is empty`, 'error'); return } await copy(value, label) } catch (e) { toast(e.message, 'error') }
}
async function otp(r) {
  try { const { value, remaining } = await call('field', { id: r.id, name: 'totp' }); await copy(value, `Code (${remaining} s left)`) } catch (e) { toast(e.message, 'error') }
}

function generate() {
  let pw = generatePassword({ length: 20 })
  const out = h('div', { class: 'gen-out mono' }, pw)
  const again = () => { pw = generatePassword({ length: 20 }); out.textContent = pw }
  const box = h('div', { class: 'pop-body' }, h('div', { class: 'pop-section' }, 'Generated password'), h('div', { class: 'pop-gen' }, out,
    h('button', { class: 'btn btn-icon btn-sm', type: 'button', title: 'Regenerate', 'aria-label': 'Regenerate', on: { click: again } }, icon('refresh')),
    h('button', { class: 'btn btn-primary btn-sm', type: 'button', on: { click: () => copy(pw, 'Password') } }, 'Copy')))
  document.querySelector('.pop-body').prepend(box)
}

refresh().catch((e) => mount(root, h('p', { class: 'alert alert-error', role: 'alert' }, e.message)))
