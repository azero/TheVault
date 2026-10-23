import { h, icon, mount, toast } from './ui.js'

const root = document.getElementById('root')

async function call(type, payload = {}) {
  const r = await chrome.runtime.sendMessage({ type, ...payload })
  if (!r || r.error) throw new Error(r?.error?.message || 'The extension is not ready.')
  return r.data
}

async function render() {
  const st = await call('status')
  const never = await call('neverList')
  const server = h('input', { class: 'input', id: 'server', type: 'url', value: st.server ?? '', placeholder: 'https://vault.example.com', autocomplete: 'off' })
  const msg = h('div', { role: 'alert', class: 'small' })
  const idle = h('select', { class: 'input', id: 'idle', on: { change: async (e) => { await call('setPrefs', { prefs: { idleMinutes: Number(e.target.value) } }); toast('Saved') } } },
    ...[[1, '1 minute'], [5, '5 minutes'], [15, '15 minutes'], [30, '30 minutes'], [60, '1 hour']].map(([m, l]) => h('option', { value: m, selected: st.prefs.idleMinutes === m }, l)))
  const clip = h('select', { class: 'input', id: 'clip', on: { change: async (e) => { await call('setPrefs', { prefs: { clipboardSeconds: Number(e.target.value) } }); toast('Saved') } } },
    ...[[0, 'Never'], [15, '15 seconds'], [30, '30 seconds'], [60, '1 minute']].map(([s, l]) => h('option', { value: s, selected: st.prefs.clipboardSeconds === s }, l)))
  const offline = h('input', { type: 'checkbox', id: 'offline', checked: st.prefs.offlineCache, on: { change: async (e) => { await call('setPrefs', { prefs: { offlineCache: e.target.checked } }); toast('Saved. Applies from the next unlock.') } } })
  mount(root, h('section', { class: 'auth-card wide' }, h('h1', { class: 'logo-h' }, h('img', { class: 'logo', src: 'brand/logo-nav.webp', alt: 'TheVault', width: 240, height: 80 })), h('h2', {}, 'Extension settings'),
    h('form', { class: 'stack', novalidate: true, on: { submit: async (e) => {
      e.preventDefault()
      try { await call('configure', { server: server.value }); msg.textContent = 'Saved. If you changed the address you need to sign in again.'; render() } catch (err) { msg.textContent = err.message }
    } } },
    h('div', { class: 'field' }, h('label', { class: 'label', for: 'server' }, 'Vault address'), server, h('span', { class: 'hint' }, 'Changing it signs you out and removes the offline copy.'), msg), h('button', { class: 'btn btn-primary', type: 'submit' }, 'Save address')),
    h('div', { class: 'stack' },
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'idle' }, 'Lock after'), idle, h('span', { class: 'hint' }, 'Also locks when the screen locks or the browser closes.')),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'clip' }, 'Clear copied passwords after'), clip),
      h('label', { class: 'check' }, offline, h('span', {}, 'Keep an encrypted offline copy so I can unlock when the server is unreachable')),
      h('p', { class: 'small muted' }, 'Keyboard shortcut for filling: ', h('span', { class: 'kbd' }, 'Ctrl+Shift+L'), ' (change it at chrome://extensions/shortcuts).')),
    never.length ? h('div', { class: 'stack' }, h('h3', {}, 'Never ask to save on'), h('ul', { class: 'history' }, never.map((host) => h('li', {}, h('span', { class: 'truncate' }, host), h('span', { class: 'spacer' }), h('button', { class: 'btn btn-sm', type: 'button', on: { click: async () => { await call('neverRemove', { host }); render() } } }, 'Remove'))))) : null,
    h('div', { class: 'cluster' }, st.signedIn ? h('button', { class: 'btn btn-danger', type: 'button', on: { click: async () => { await call('signOut'); toast('Signed out'); render() } } }, icon('logout', 'icon-sm'), 'Sign out') : null,
      h('span', { class: 'muted small' }, st.user ? `Signed in as ${st.user.email}` : 'Not signed in'))))
}
render()
