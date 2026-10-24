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
  const section = (title, ...kids) => h('section', { class: 'opt-section stack' }, h('h3', {}, title), ...kids)
  mount(root, h('section', { class: 'auth-card wide' }, h('h1', { class: 'logo-h' }, h('img', { class: 'logo', src: 'brand/logo-nav.webp', alt: 'TheVault', width: 240, height: 80 })), h('h2', {}, 'Extension settings'),
    section('Connection',
      h('form', { class: 'stack', novalidate: true, on: { submit: async (e) => {
        e.preventDefault()
        try { await call('configure', { server: server.value }); toast('Saved. If you changed the address you need to sign in again.', 'ok', 4500); render() } catch (err) { msg.textContent = err.message }
      } } },
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'server' }, 'Vault address'), server, h('span', { class: 'hint' }, 'Changing it signs you out and removes the offline copy.'), msg), h('div', { class: 'cluster' }, h('button', { class: 'btn btn-primary', type: 'submit' }, 'Save address'), st.server ? h('a', { class: 'btn', href: st.server, target: '_blank', rel: 'noopener' }, icon('external', 'icon-sm'), 'Open TheVault') : null)),
      h('div', { class: 'cluster' }, st.signedIn ? h('button', { class: 'btn btn-danger btn-sm', type: 'button', on: { click: async () => { await call('signOut'); toast('Signed out'); render() } } }, icon('logout', 'icon-sm'), 'Sign out') : null,
        h('span', { class: 'muted small' }, st.user ? `Signed in as ${st.user.email}` : 'Not signed in'))),
    section('Security',
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'idle' }, 'Lock after'), idle, h('span', { class: 'hint' }, 'Also locks when the screen locks or the browser closes.')),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'clip' }, 'Clear copied passwords after'), clip),
      h('label', { class: 'check' }, offline, h('span', {}, 'Keep an encrypted offline copy so I can unlock when the server is unreachable'))),
    section('Filling',
      h('p', { class: 'small muted' }, 'Click the TheVault icon and choose ', h('strong', {}, 'Fill'), ', or press ', h('span', { class: 'kbd' }, 'Ctrl+Shift+L'), ' (', h('span', { class: 'kbd' }, '⌘⇧L'), ' on a Mac) on the login page. Nothing is ever filled by itself. You can change the shortcut at ', h('code', {}, 'chrome://extensions/shortcuts'), '.'),
      never.length ? h('div', { class: 'stack' }, h('h4', {}, 'Never ask to save on'), h('ul', { class: 'history' }, never.map((host) => h('li', {}, h('span', { class: 'truncate' }, host), h('span', { class: 'spacer' }), h('button', { class: 'btn btn-sm', type: 'button', on: { click: async () => { await call('neverRemove', { host }); render() } } }, 'Remove'))))) : null),
    h('p', { class: 'small muted opt-about' }, `TheVault extension ${chrome.runtime.getManifest().version}. To update, download it again from TheVault (Settings, Browser extension), replace the files in the same folder and press the reload icon on this extension at chrome://extensions.`)))
}
render()
