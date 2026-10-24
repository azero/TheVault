import { h, icon, toast, timeAgo, fmtDateTime, mount } from './dom.js'
import { get, post, del, put, ApiError } from './api.js'
import { href, navigate } from './router.js'
import { isAdmin, vault, changeMasterPassword, rotateRecoveryKey, eraseOwnVault, ownFingerprint, importItems, exportable, reportClientEvent, verifyPassword, live, spaceName } from './vault.js'
import { pageHead, spinner, strengthMeter, emptyState } from './components.js'
import { extensionInfo, browserKey, canRunExtension, formatSize, rememberExtensionPrompt, BROWSERS } from './extension-promo.js'
import { alertBox, confirmDialog, passwordDialog, infoDialog } from './dialog.js'
import { prefs, applyTheme } from './prefs.js'
import { MIN_PASSWORD, recoveryKitText } from './auth.js'
import { estimateStrength } from '../core/strength.js'
import { importCsv, importJson, exportCsv, exportJson } from '../core/csv.js'
import { exportEncrypted, importEncrypted } from '../core/exportfmt.js'
import { DEFAULT_ITERATIONS } from '../core/crypto.js'

const TABS = [['account', 'Account'], ['security', 'Security'], ['devices', 'Devices'], ['activity', 'Activity'], ['data', 'Import & export'], ['extension', 'Browser extension']]

export function settingsView(ctx) {
  const tab = TABS.some(([k]) => k === ctx.route.seg[1]) ? ctx.route.seg[1] : 'account'
  const body = h('div', {}, spinner('Loading…'))
  const views = { account, security, devices, activity, data, extension }
  Promise.resolve(views[tab](ctx)).then((n) => mount(body, n)).catch((e) => mount(body, alertBox('error', e.message)))
  return h('div', {}, pageHead('Settings'), h('nav', { class: 'tabs', 'aria-label': 'Settings' }, TABS.map(([k, l]) => h('a', { href: href('/settings/' + k), 'aria-current': k === tab ? 'page' : null }, l))), body)
}

function download(name, text, type = 'text/plain') {
  const a = h('a', { href: '#' })
  const url = URL.createObjectURL(new Blob([text], { type }))
  a.href = url; a.download = name
  document.body.append(a); a.click(); a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 5000)
}

// ---------- account ----------
async function account() {
  const u = vault.me
  const fp = await ownFingerprint()
  const idle = h('select', { class: 'input', id: 'idle', on: { change: async (e) => {
    try { await put('/settings', { idle_lock_minutes: Number(e.target.value) }); vault.session.idle_lock_minutes = Number(e.target.value); toast('Auto-lock updated') } catch (x) { toast(x.message, 'error') }
  } } }, ...[[1, '1 minute'], [5, '5 minutes'], [15, '15 minutes'], [30, '30 minutes'], [60, '1 hour'], [240, '4 hours'], [480, '8 hours']].map(([m, l]) => h('option', { value: m, selected: vault.session.idle_lock_minutes === m }, l)))
  const clip = h('select', { class: 'input', id: 'clip', on: { change: (e) => { prefs.set('clipboardSeconds', Number(e.target.value)); toast('Saved') } } }, ...[[0, 'Never'], [15, '15 seconds'], [30, '30 seconds'], [60, '1 minute'], [120, '2 minutes']].map(([s, l]) => h('option', { value: s, selected: prefs.get('clipboardSeconds') === s }, l)))
  const theme = h('select', { class: 'input', id: 'theme', on: { change: (e) => { prefs.set('theme', e.target.value); applyTheme(e.target.value) } } }, ...[['auto', 'Match my system'], ['light', 'Light'], ['dark', 'Dark']].map(([v, l]) => h('option', { value: v, selected: prefs.get('theme') === v }, l)))
  return h('div', { class: 'grid-2' },
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Profile')), h('div', { class: 'card-body' }, h('dl', { class: 'kv' },
      h('dt', {}, 'Name'), h('dd', {}, u.name || '—'), h('dt', {}, 'Email'), h('dd', {}, u.email), h('dt', {}, 'Role'), h('dd', {}, u.role === 'admin' ? 'Administrator' : 'Member'), h('dt', {}, 'Sign-in'), h('dd', {}, 'ClosedDoor'),
      h('dt', {}, 'Key fingerprint'), h('dd', {}, h('span', { class: 'fp' }, fp))), h('p', { class: 'hint' }, 'Colleagues see this when you share a space with them. Your name and email come from ClosedDoor.'))),
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Preferences')), h('div', { class: 'card-body stack' },
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'idle' }, 'Lock the vault after'), idle, h('span', { class: 'hint' }, 'Of inactivity. Applies to the web app and the browser extension.')),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'clip' }, 'Clear copied passwords after'), clip, h('span', { class: 'hint' }, 'This browser only.')),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'theme' }, 'Theme'), theme))))
}

// ---------- security ----------
function pwForm({ title, current, onSubmit, submitLabel }) {
  const cur = current ? h('input', { class: 'input', id: 'cur', type: 'password', autocomplete: 'current-password', required: true }) : null
  const n1 = h('input', { class: 'input', id: 'n1', type: 'password', autocomplete: 'new-password', required: true, minlength: MIN_PASSWORD })
  const n2 = h('input', { class: 'input', id: 'n2', type: 'password', autocomplete: 'new-password', required: true })
  const meter = strengthMeter(() => n1.value)
  n1.addEventListener('input', () => meter.update())
  const msg = h('div', { 'aria-live': 'polite' })
  const btn = h('button', { class: 'btn btn-primary', type: 'submit' }, submitLabel)
  const form = h('form', { class: 'stack', novalidate: true, on: { submit: async (e) => {
    e.preventDefault()
    const problem = n1.value.length < MIN_PASSWORD ? `Use at least ${MIN_PASSWORD} characters.` : estimateStrength(n1.value).score < 2 ? 'That password is too easy to guess.' : n1.value !== n2.value ? 'The two passwords do not match.' : ''
    if (problem) { mount(msg, alertBox('error', problem)); return }
    btn.disabled = true; mount(msg, null)
    try { await onSubmit(cur?.value, n1.value); form.reset(); meter.update() } catch (x) { mount(msg, alertBox('error', x instanceof ApiError && x.code === 'bad_password' ? 'The current master password is not correct.' : x.message)) } finally { btn.disabled = false }
  } } },
  cur ? h('div', { class: 'field' }, h('label', { class: 'label', for: 'cur' }, 'Current master password'), cur) : null,
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'n1' }, 'New master password'), n1, meter.el),
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'n2' }, 'Repeat new master password'), n2), msg, btn)
  return form
}

async function security() {
  const kitBox = h('div')
  const showKey = async (key, title) => {
    mount(kitBox, h('div', { class: 'stack' }, alertBox('warn', 'Save this key now. It replaces your old recovery key, which no longer works, and it will not be shown again.'),
      h('div', { class: 'recovery' }, key.split('-').join(' ')),
      h('div', { class: 'cluster' }, h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => download('thevault-recovery-key.txt', recoveryKitText(key, vault.me.email)) } }, icon('download', 'icon-sm'), 'Download'),
        h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => window.print() } }, icon('print', 'icon-sm'), 'Print'),
        h('button', { class: 'btn btn-sm btn-ghost', type: 'button', on: { click: () => mount(kitBox, null) } }, 'I saved it, hide'))))
  }
  const iterations = vault.kdf?.iterations ?? 0
  return h('div', { class: 'stack' },
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Master password')), h('div', { class: 'card-body' },
      h('p', { class: 'muted' }, 'Changing it signs out all your other browsers and devices. Your items do not need re-encrypting.'),
      pwForm({ current: true, submitLabel: 'Change master password', onSubmit: async (cur, nw) => {
        const r = await changeMasterPassword(cur, nw); toast(`Master password changed${r.sessions_ended ? `. ${r.sessions_ended} other session(s) signed out` : ''}`)
      } }))),
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Recovery key')), h('div', { class: 'card-body stack' },
      h('p', { class: 'muted' }, 'Lost your master password? The recovery key restores access. Generate a new one if you lost the old one or someone may have seen it.'),
      h('div', {}, h('button', { class: 'btn', type: 'button', on: { click: async () => {
        const pw = await passwordDialog({ title: 'Create a new recovery key', body: 'Enter your master password. The old recovery key will stop working.', confirm: 'Create key', verify: verifyPassword })
        if (!pw) return
        try { await showKey(await rotateRecoveryKey(pw)) } catch (e) { toast(e.message, 'error') }
      } } }, icon('key', 'icon-sm'), 'Create a new recovery key')), kitBox)),
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Encryption')), h('div', { class: 'card-body' },
      h('dl', { class: 'kv' }, h('dt', {}, 'Key derivation'), h('dd', {}, 'PBKDF2-HMAC-SHA256'), h('dt', {}, 'Iterations'), h('dd', {}, iterations.toLocaleString()), h('dt', {}, 'Item encryption'), h('dd', {}, 'AES-256-GCM'), h('dt', {}, 'Sharing'), h('dd', {}, 'ECDH P-256 + ECDSA signatures')),
      iterations < DEFAULT_ITERATIONS ? h('p', { class: 'hint' }, 'Your vault uses fewer iterations than the current default. Changing your master password upgrades it.') : null)),
    h('div', { class: 'card card-danger' }, h('div', { class: 'card-head' }, h('h2', {}, 'Delete my vault')), h('div', { class: 'card-body' },
      h('p', { class: 'muted' }, 'Permanently deletes all your items, your recovery key and your space memberships. Items in spaces others own stay with them.'),
      h('button', { class: 'btn btn-danger', type: 'button', on: { click: async () => {
        if (!(await confirmDialog({ title: 'Delete your vault?', body: 'This cannot be undone. Export first if you need a copy.', confirm: 'Continue', danger: true }))) return
        const pw = await passwordDialog({ title: 'Confirm with your master password', body: 'Enter your master password to delete the vault.', confirm: 'Delete my vault', danger: true, verify: verifyPassword })
        if (!pw) return
        try { await eraseOwnVault(pw); toast('Vault deleted'); location.assign('/') } catch (e) { toast(e.message, 'error') }
      } } }, icon('trash', 'icon-sm'), 'Delete my vault'))))
}

// ---------- devices ----------
async function devices() {
  const wrap = h('div', { class: 'stack' })
  const load = async () => {
    const { sessions } = await get('/sessions')
    const rows = sessions.map((s) => h('tr', {},
      h('td', { 'data-label': 'Device' }, h('div', { class: 'cluster' }, icon(s.kind === 'ext' ? 'puzzle' : 'monitor'), h('div', {}, h('strong', {}, s.label || (s.kind === 'ext' ? 'Browser extension' : 'Browser')), s.current ? h('span', { class: 'badge badge-ok' }, 'This device') : null, h('div', { class: 'muted small' }, s.kind === 'ext' ? 'Extension' : 'Web')))),
      h('td', { 'data-label': 'Address' }, h('span', { class: 'mono' }, s.ip || '—')),
      h('td', { 'data-label': 'Last active' }, timeAgo(s.last_seen)),
      h('td', { 'data-label': 'State' }, s.unlocked ? h('span', { class: 'badge badge-warn' }, icon('unlock', 'icon-sm'), 'Unlocked') : h('span', { class: 'badge' }, icon('lock', 'icon-sm'), 'Locked')),
      h('td', {}, s.current ? null : h('button', { class: 'btn btn-sm', type: 'button', on: { click: async () => { try { await del('/sessions/' + s.id); toast('Signed out'); load() } catch (e) { toast(e.message, 'error') } } } }, 'Sign out'))))
    mount(wrap, h('p', { class: 'muted' }, 'Browsers and extensions signed in to your account. Sign out any you do not recognise, then change your master password.'),
      h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Signed-in devices' }, h('table', { class: 'table table-stack' }, h('thead', {}, h('tr', {}, ['Device', 'Address', 'Last active', 'State', ''].map((x) => h('th', {}, x)))), h('tbody', {}, rows))),
      sessions.length > 1 ? h('div', {}, h('button', { class: 'btn', type: 'button', on: { click: async () => { if (await confirmDialog({ title: 'Sign out everywhere else?', body: 'Every other browser and extension will be signed out.', confirm: 'Sign out others' })) { const r = await post('/sessions/revoke-others'); toast(`${r.revoked} signed out`); load() } } } }, icon('logout', 'icon-sm'), 'Sign out all other devices')) : null)
  }
  await load()
  return wrap
}

// ---------- activity ----------
const EVENT_LABELS = {
  login: 'Signed in', logout: 'Signed out', unlock: 'Vault unlocked', lock: 'Vault locked', unlock_failed: 'Wrong master password', unlock_lockout: 'Locked out after wrong passwords', vault_created: 'Vault created',
  master_password_changed: 'Master password changed', recovery_used: 'Recovery key used', recovery_failed: 'Wrong recovery key', recovery_rotated: 'New recovery key created', ext_device_added: 'Extension signed in', sync_full: 'Full vault download',
  item_created: 'Item added', item_updated: 'Item changed', item_deleted: 'Item moved to trash', item_purged: 'Item deleted', item_restored: 'Item restored', items_imported: 'Items imported', vault_export: 'Vault exported (plain)', vault_export_encrypted: 'Vault exported (encrypted)',
  space_created: 'Space created', space_deleted: 'Space deleted', space_member_added: 'Member added', space_member_removed: 'Member removed', space_member_role_changed: 'Role changed', space_key_rotated: 'Space key rotated', space_left: 'Left a space',
  session_revoked_by_user: 'Device signed out', sessions_revoked_by_user: 'Devices signed out', session_ip_changed: 'Network address changed', csrf_failed: 'Request refused (CSRF)', origin_refused: 'Request refused (origin)', login_denied: 'Sign-in denied', admin_user_locked: 'Account locked by an administrator',
  admin_user_unlocked: 'Account unlocked by an administrator', admin_sessions_revoked: 'Devices signed out by an administrator', admin_vault_erased: 'Vault erased by an administrator',
}
export const eventLabel = (e) => EVENT_LABELS[e] ?? e.replace(/_/g, ' ')
export function eventBadge(r) {
  const bad = r.outcome === 'failure' || /failed|lockout|refused|denied|erased|locked$/.test(r.event)
  return h('span', { class: 'badge ' + (bad ? 'badge-danger' : /export|password_changed|recovery|key_rotated|admin_/.test(r.event) ? 'badge-warn' : '') }, eventLabel(r.event))
}

async function activity() {
  const { events } = await get('/activity')
  if (!events.length) return emptyState('activity', 'No activity yet', 'Security events for your account appear here.')
  return h('div', { class: 'stack' }, h('p', { class: 'muted' }, 'Everything that happened to your account. If something here is not you, sign out other devices and change your master password.'),
    h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Account activity' }, h('table', { class: 'table table-stack' }, h('thead', {}, h('tr', {}, ['When', 'Event', 'Address'].map((x) => h('th', {}, x)))),
      h('tbody', {}, events.map((r) => h('tr', {}, h('td', { 'data-label': 'When', title: fmtDateTime(r.created_at) }, timeAgo(r.created_at)), h('td', { 'data-label': 'Event' }, eventBadge(r)), h('td', { 'data-label': 'Address' }, h('span', { class: 'mono' }, r.ip || '—'))))))))
}

// ---------- import / export ----------
async function data() {
  const status = h('div', { 'aria-live': 'polite' })
  const file = h('input', { class: 'input', id: 'imp-file', type: 'file', accept: '.csv,.json,text/csv,application/json' })
  const preview = h('div', { class: 'stack' })
  file.addEventListener('change', async () => {
    mount(preview, null); mount(status, null)
    const f = file.files[0]
    if (!f) return
    if (f.size > 20 << 20) { mount(status, alertBox('error', 'That file is larger than 20 MB.')); return }
    const text = await f.text()
    try {
      let res
      if (/^\s*\{/.test(text)) {
        const j = JSON.parse(text)
        if (j.format === 'thevault-export') {
          const pw = await passwordDialog({ title: 'Encrypted export', body: 'Enter the password you chose when you created this export file.', confirm: 'Decrypt' })
          if (!pw) return
          res = await importEncrypted(text, pw)
        } else res = importJson(text)
      } else res = importCsv(text)
      const go = h('button', { class: 'btn btn-primary', type: 'button' }, `Import ${res.items.length} item${res.items.length === 1 ? '' : 's'}`)
      go.addEventListener('click', async () => {
        go.disabled = true
        try { const n = await importItems(res.items, (d, t) => { go.textContent = `Importing ${d} of ${t}…` }); reportClientEvent('vault_import_file', n); toast(`${n} items imported`); navigate('/all') } catch (e) { mount(status, alertBox('error', e.message)); go.disabled = false }
      })
      mount(preview, alertBox('info', `Found ${res.items.length} item${res.items.length === 1 ? '' : 's'} (${res.format})${res.skipped ? `, ${res.skipped} empty row(s) skipped` : ''}. Nothing is imported until you confirm.`),
        h('ul', { class: 'history' }, res.items.slice(0, 5).map((i) => h('li', {}, h('strong', {}, i.name || '(untitled)'), h('span', { class: 'muted' }, i.data.username || i.urls[0]?.url || '')))), res.items.length > 5 ? h('p', { class: 'muted small' }, `…and ${res.items.length - 5} more`) : null, go)
    } catch (e) { mount(status, alertBox('error', e.message?.includes('decryption failed') ? 'Wrong password for this export file.' : e.message)) }
  })

  const scope = h('select', { class: 'input', id: 'exp-scope' }, h('option', { value: 'all' }, 'Everything I can see'), h('option', { value: 'personal' }, 'Personal items only'), ...[...vault.spaces.values()].map((s) => h('option', { value: s.id }, 'Space: ' + s.name)))
  const exp = (kind) => async () => {
    if (!exportable(scope.value).length) { toast('Nothing to export', 'error'); return }
    // The plaintext is gathered only after the dialog returns, from live state: locking while it was open closes it, and an
    // unlocked vault is required to get anything at all.
    const gather = () => (vault.keyring ? exportable(scope.value) : [])
    let items = []
    if (kind === 'enc') {
      const pw = await passwordDialog({ title: 'Protect the export', body: 'Choose a password for the export file. You can use your master password or a different one.', confirm: 'Export' })
      if (!pw || !(items = gather()).length) return
      download(`thevault-export-${new Date().toISOString().slice(0, 10)}.json`, await exportEncrypted(items, pw), 'application/json')
      reportClientEvent('vault_export_encrypted', items.length)
    } else {
      const pw = await passwordDialog({ title: 'Export unencrypted data', body: h('span', {}, h('strong', {}, 'The file will contain every password in plain text. '), 'Delete it as soon as you have used it. Enter your master password to continue.'), confirm: 'Export', danger: true, verify: verifyPassword })
      if (!pw || !(items = gather()).length) return
      if (kind === 'csv') download(`thevault-export-${new Date().toISOString().slice(0, 10)}.csv`, exportCsv(items), 'text/csv')
      else download(`thevault-export-${new Date().toISOString().slice(0, 10)}.json`, exportJson(items), 'application/json')
      reportClientEvent('vault_export', items.length)
    }
    toast('Export downloaded')
  }
  const allowPlain = vault.session.can_plain_export
  return h('div', { class: 'grid-2' },
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Import')), h('div', { class: 'card-body stack' },
      h('p', { class: 'muted' }, 'Supports CSV exports from Chrome, Edge, Bitwarden, 1Password and LastPass, and TheVault JSON. The file is read in your browser and encrypted before upload.'),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'imp-file' }, 'Choose a file'), file), status, preview)),
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Export')), h('div', { class: 'card-body stack' },
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'exp-scope' }, 'What to export'), scope),
      h('div', { class: 'cluster' }, h('button', { class: 'btn btn-primary', type: 'button', on: { click: exp('enc') } }, icon('download', 'icon-sm'), 'Encrypted file (recommended)')),
      allowPlain ? h('div', { class: 'cluster' }, h('button', { class: 'btn', type: 'button', on: { click: exp('json') } }, 'Plain JSON'), h('button', { class: 'btn', type: 'button', on: { click: exp('csv') } }, 'Plain CSV (logins and notes)')) : h('p', { class: 'muted small' }, 'Plain-text export is disabled by your administrator.'),
      h('p', { class: 'hint' }, 'Exports are recorded in your activity log and reported to security monitoring.'))))
}

// ---------- extension ----------
async function extension() {
  const [info, which] = await Promise.all([extensionInfo(), browserKey()])
  const ids = vault.session.extension_ids ?? []
  const supported = canRunExtension()
  const copyAddress = async (address) => { try { await navigator.clipboard.writeText(address); toast('Copied. Paste it into the address bar.') } catch { toast('Copying was blocked. Type the address instead.', 'error') } }
  const dl = h('a', { class: 'btn btn-primary', href: '/download/extension.zip', download: info.filename || 'thevault-extension.zip', on: { click: rememberExtensionPrompt } }, icon('download', 'icon-sm'), 'Download extension')

  const notices = []
  if (!info.available) notices.push(alertBox('warn', isAdmin()
    ? 'This build of TheVault does not include the extension package. Deploy the official image (it packages the extension), or run `npm run build:extension` and load the extension/ folder with “Load unpacked”.'
    : 'This copy of TheVault does not include the extension package yet. Ask your administrator.'))
  if (!ids.length) notices.push(alertBox('warn', isAdmin()
    ? 'No extension id is allowed yet, so the extension cannot sign in. Set VAULT_EXTENSION_IDS to the extension id (the one shipped with TheVault is gfnpigdeagehjmdcmkijcmgfadlpnlbl) and restart the server.'
    : 'Your administrator has not switched the extension on for sign-in yet. You can install it now; it starts working once they do.'))
  if (!supported) notices.push(alertBox('info', 'This browser cannot run the extension. It needs Chrome, Edge, Brave, Vivaldi or Opera on a computer (version 116 or newer). Firefox, Safari and phone browsers are not supported: on those, use this web app.'))

  const browsers = h('ul', { class: 'ext-browsers' }, BROWSERS.map(([key, name, address]) => h('li', { class: key === which ? 'you' : '' },
    h('span', { class: 'name' }, name, key === which ? h('span', { class: 'badge badge-ok' }, 'This browser') : null),
    h('code', {}, address),
    h('button', { class: 'btn btn-sm', type: 'button', 'aria-label': `Copy the ${name} extensions address`, on: { click: () => copyAddress(address) } }, icon('copy', 'icon-sm'), 'Copy'))))

  const install = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Install the extension')), h('div', { class: 'card-body stack' },
    h('p', {}, 'Fill logins, copy one-time codes and save new passwords right from the browser. It uses the same encryption as this page and locks itself when you are idle.'),
    ...notices,
    info.available ? h('div', { class: 'ext-meta' }, dl, h('span', { class: 'muted small' }, `Version ${info.version} · ${formatSize(info.size)}`)) : null,
    h('ol', { class: 'ext-steps' },
      h('li', {}, h('strong', {}, 'Download'), ' the file and unzip it into a folder you will keep, for example ', h('code', {}, 'Documents/TheVault extension'), '. The browser runs the extension from that folder, so do not delete it.'),
      h('li', {}, h('strong', {}, 'Open the extensions page'), ' of your browser (browsers do not let a web page open it, so copy the address and paste it into a new tab):', browsers),
      h('li', {}, 'Turn on ', h('strong', {}, 'Developer mode'), ', choose ', h('strong', {}, 'Load unpacked'), ' and select the unzipped folder.'),
      h('li', {}, 'Click the puzzle-piece icon in the toolbar and ', h('strong', {}, 'pin'), ' TheVault. Click it, check that the address is yours, press ', h('strong', {}, 'Continue'), ', sign in with ClosedDoor and unlock with your master password.')),
    h('details', { class: 'ext-verify' }, h('summary', {}, 'Check the download'),
      info.available ? h('div', { class: 'stack-sm' },
        h('p', { class: 'muted small' }, 'SHA-256 of the file you download from this page:'), h('code', { class: 'ext-hash' }, info.sha256),
        h('p', { class: 'muted small' }, 'Windows: ', h('code', {}, 'certutil -hashfile thevault-extension.zip SHA256'), ' · macOS and Linux: ', h('code', {}, 'shasum -a 256 thevault-extension.zip'))) : h('p', { class: 'muted small' }, 'Nothing to check: there is no package in this build.')),
    h('div', {}, h('h3', {}, 'Updating'), h('p', { class: 'muted' }, 'When this page shows a newer version than the one on the extension’s own settings page, download it again, replace the files in the same folder and press the reload icon on the extension’s card in the extensions page. You stay signed in and your settings are kept.'))))

  const using = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Using it')), h('div', { class: 'card-body' }, h('ul', { class: 'assure' },
    ...[['key', 'On a login page, click the TheVault icon and choose Fill, or press Ctrl+Shift+L (Cmd+Shift+L on a Mac).'], ['copy', 'In the list, copy a username, password or one-time code. Copied passwords are cleared from the clipboard after a while.'],
      ['plus', 'Log in to a site as usual and the extension offers to save the new login. Choose Never for sites you do not want saved.'], ['lock', 'Lock it from the icon at any time. It also locks after the idle time and when you close the browser.']].map(([ic, t]) => h('li', {}, icon(ic), h('span', {}, t))))))
  const safe = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'How it protects you')), h('div', { class: 'card-body' }, h('ul', { class: 'assure' },
    ...[['shield', 'It never fills a page by itself. You choose the login, or press Ctrl+Shift+L (Cmd+Shift+L on Mac).'], ['globe', 'It fills only on an exact match with the website you saved, never on look-alike addresses, never inside other sites’ frames.'],
      ['lock', 'Your master password is typed only into the extension’s own popup, never into a web page.'], ['clock', 'It locks after the idle time you set in Account settings.']].map(([ic, t]) => h('li', {}, icon(ic), h('span', {}, t))))))
  return h('div', { class: 'grid-2' }, install, h('div', { class: 'stack' }, using, safe))
}
