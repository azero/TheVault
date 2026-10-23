// Administration: accounts, security monitoring, SkyNet status. Metadata only: there is no way to see vault content.
import { h, icon, toast, timeAgo, fmtDateTime, fmtBytes, avatarClass, initials, mount } from './dom.js'
import { get, post } from './api.js'
import { href } from './router.js'
import { vault } from './vault.js'
import { pageHead, spinner, emptyState } from './components.js'
import { alertBox, confirmDialog, modal } from './dialog.js'
import { eventBadge } from './settings.js'

const TABS = [['overview', 'Overview'], ['users', 'People'], ['audit', 'Audit log'], ['skynet', 'SkyNet']]

export function adminView(ctx) {
  if (vault.me.role !== 'admin') return alertBox('error', 'Administrators only.')
  const tab = TABS.some(([k]) => k === ctx.route.seg[1]) ? ctx.route.seg[1] : 'overview'
  const body = h('div', {}, spinner('Loading…'))
  const views = { overview, users, audit, skynet }
  Promise.resolve(views[tab](ctx)).then((n) => mount(body, n)).catch((e) => mount(body, alertBox('error', e.message)))
  return h('div', {}, pageHead('Administration', 'Accounts and security monitoring. Administrators can never read anyone’s vault: the server only holds ciphertext.'),
    h('nav', { class: 'tabs', 'aria-label': 'Administration' }, TABS.map(([k, l]) => h('a', { href: href('/admin/' + k), 'aria-current': k === tab ? 'page' : null }, l))), body)
}

const stat = (n, l) => h('div', { class: 'stat' }, h('span', { class: 'n' }, String(n)), h('span', { class: 'l' }, l))

async function overview() {
  const o = await get('/admin/overview')
  const s = o.stats
  const sky = o.skynet
  return h('div', { class: 'stack' },
    h('div', { class: 'stats' }, stat(s.Users, 'People'), stat(s.Vaults, 'Vaults'), stat(s.Items, 'Items (encrypted)'), stat(s.Spaces, 'Spaces'), stat(s.Sessions, 'Active sessions')),
    h('div', { class: 'grid-2' },
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Server')), h('div', { class: 'card-body' }, h('dl', { class: 'kv' }, h('dt', {}, 'Version'), h('dd', {}, o.version), h('dt', {}, 'Database'), h('dd', {}, fmtBytes(s.DBBytes)), h('dt', {}, 'Audit rows'), h('dd', {}, String(s.AuditRows))))),
      h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'SkyNet protection'), sky ? h('span', { class: 'badge ' + (sky.last_error ? 'badge-danger' : 'badge-ok') }, sky.last_error ? 'Problem' : 'Connected') : h('span', { class: 'badge badge-warn' }, 'Not configured')),
        h('div', { class: 'card-body' }, sky ? h('dl', { class: 'kv' }, h('dt', {}, 'Last event sent'), h('dd', {}, timeAgo(sky.last_send)), h('dt', {}, 'Queued'), h('dd', {}, String(sky.outbox)), h('dt', {}, 'Blocked addresses'), h('dd', {}, String(sky.deny.length)), h('dt', {}, 'Commands'), h('dd', {}, sky.commands_enabled ? 'Enabled' : 'Off (no pinned key)'))
          : alertBox('warn', 'Events are not being sent to SkyNet. Set VAULT_SKYNET_URL and an enrollment token to enable monitoring and automatic blocking.')))),
    alertBox('info', 'Everything an attacker would need is encrypted with keys derived from each person’s master password, which this server never sees.'))
}

async function users() {
  const wrap = h('div', { class: 'stack' })
  const load = async () => {
    const o = await get('/admin/overview')
    const act = (u, path, ok, confirm) => async () => {
      if (confirm && !(await confirmDialog(confirm))) return
      try { await post(`/admin/users/${u.sub}/${path}`); toast(ok); load() } catch (e) { toast(e.message, 'error') }
    }
    mount(wrap, h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'People' }, h('table', { class: 'table table-stack' },
      h('thead', {}, h('tr', {}, ['Person', 'Vault', 'Items', 'Sessions', 'Last sign-in', ''].map((x) => h('th', {}, x)))),
      h('tbody', {}, o.users.map((u) => h('tr', {},
        h('td', { 'data-label': 'Person' }, h('div', { class: 'cluster' }, h('span', { class: `avatar avatar-sm ${avatarClass(u.sub)}${u.role === 'admin' ? ' is-admin' : ''}` }, initials(u.name || u.email)),
          h('div', {}, h('strong', {}, u.name || u.email), h('div', { class: 'muted small' }, u.email), u.role === 'admin' ? h('span', { class: 'badge badge-gold' }, 'Admin') : null, u.locked ? h('span', { class: 'badge badge-danger' }, 'Locked') : null, u.locked_out ? h('span', { class: 'badge badge-warn' }, 'Password lockout') : null))),
        h('td', { 'data-label': 'Vault' }, u.has_vault ? h('span', { class: 'badge badge-ok' }, 'Set up') : h('span', { class: 'badge' }, 'None'), u.last_unlock ? h('div', { class: 'muted small' }, 'Unlocked ' + timeAgo(u.last_unlock)) : null),
        h('td', { 'data-label': 'Items' }, String(u.items)), h('td', { 'data-label': 'Sessions' }, String(u.sessions)), h('td', { 'data-label': 'Last sign-in', title: fmtDateTime(u.last_login) }, timeAgo(u.last_login)),
        h('td', {}, u.sub === vault.me.sub ? h('span', { class: 'muted small' }, 'You') : h('div', { class: 'cluster' },
          u.locked ? h('button', { class: 'btn btn-sm', type: 'button', on: { click: act(u, 'unlock', 'Account unlocked') } }, 'Unlock account')
            : h('button', { class: 'btn btn-sm', type: 'button', on: { click: act(u, 'lock', 'Account locked', { title: `Lock ${u.name || u.email}?`, body: 'They are signed out everywhere and cannot sign in until you unlock the account. Their data is not touched.', confirm: 'Lock account', danger: true }) } }, 'Lock'),
          u.sessions ? h('button', { class: 'btn btn-sm', type: 'button', on: { click: act(u, 'revoke-sessions', 'Sessions ended') } }, 'End sessions') : null,
          u.has_vault ? h('button', { class: 'btn btn-sm btn-danger', type: 'button', on: { click: () => eraseDialog(u, load) } }, 'Erase vault') : null))))))))
  }
  await load()
  return wrap
}

function eraseDialog(u, done) {
  const input = h('input', { class: 'input', id: 'erase-confirm', autocomplete: 'off' })
  return modal({
    title: `Erase ${u.name || u.email}’s vault?`,
    body: h('div', { class: 'stack' }, alertBox('error', 'This permanently deletes their encrypted items and keys. Nobody can recover them, not even you. Use it only when they have lost both their master password and recovery key.'),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'erase-confirm' }, `Type ${u.email} to confirm`), input)),
    actions: (d) => [h('button', { class: 'btn', type: 'button', on: { click: () => d(false) } }, 'Cancel'),
      h('button', { class: 'btn btn-danger', type: 'button', on: { click: async () => { try { await post(`/admin/users/${u.sub}/erase-vault`, { confirm: input.value }); toast('Vault erased'); d(true); done() } catch (e) { toast(e.message, 'error') } } } }, 'Erase vault')],
  })
}

async function audit(ctx) {
  const actor = ctx.route.query.actor || ''
  const o = await get('/admin/audit?limit=300' + (actor ? '&actor=' + encodeURIComponent(actor) : ''))
  const filter = h('input', { class: 'input', id: 'audit-q', type: 'search', placeholder: 'Filter this page', autocomplete: 'off' })
  const rows = h('tbody')
  const draw = () => {
    const q = filter.value.toLowerCase()
    mount(rows, o.events.filter((r) => !q || `${r.event} ${r.actor} ${r.target} ${r.ip} ${r.details}`.toLowerCase().includes(q)).map((r) => h('tr', {},
      h('td', { 'data-label': 'When', title: fmtDateTime(r.created_at) }, h('span', { class: 'nowrap' }, new Date(r.created_at * 1000).toLocaleString())), h('td', { 'data-label': 'Event' }, eventBadge(r)),
      h('td', { 'data-label': 'Person' }, r.actor ? h('a', { href: href('/admin/audit', { actor: r.actor }), class: 'mono small', title: r.actor }, r.actor.slice(0, 8) + '…') : '—'),
      h('td', { 'data-label': 'Address' }, h('span', { class: 'mono' }, r.ip || '—')), h('td', { 'data-label': 'Details' }, h('span', { class: 'small muted' }, [r.target && 'target=' + r.target.slice(0, 12), r.details].filter(Boolean).join(' ') )))))
  }
  filter.addEventListener('input', draw)
  draw()
  return h('div', { class: 'stack' }, h('div', { class: 'cluster' }, h('div', { class: 'field' }, h('label', { class: 'sr-only', for: 'audit-q' }, 'Filter'), filter), actor ? h('a', { class: 'btn btn-sm', href: href('/admin/audit') }, 'Clear person filter') : null),
    o.events.length ? h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Audit log' }, h('table', { class: 'table table-stack' }, h('thead', {}, h('tr', {}, ['When', 'Event', 'Person', 'Address', 'Details'].map((x) => h('th', {}, x)))), rows)) : emptyState('activity', 'No events', ''))
}

async function skynet() {
  const o = await get('/admin/overview')
  const s = o.skynet
  if (!s) return h('div', { class: 'stack' }, alertBox('warn', 'SkyNet is not configured.'), h('p', { class: 'muted' }, 'Set VAULT_SKYNET_URL and VAULT_SKYNET_ENROLL_TOKEN (create the token in SkyNet under Agents, type “PHP / web adapter”). The vault then ships every security event to SkyNet and enforces its signed block commands. See docs/skynet.md.'))
  return h('div', { class: 'stack' },
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Connection')), h('div', { class: 'card-body' }, h('dl', { class: 'kv' },
      h('dt', {}, 'SkyNet'), h('dd', {}, s.url), h('dt', {}, 'Agent id'), h('dd', {}, s.agent_id), h('dt', {}, 'Events sent'), h('dd', {}, String(s.sent)), h('dt', {}, 'Last sent'), h('dd', {}, timeAgo(s.last_send)),
      h('dt', {}, 'Waiting to send'), h('dd', {}, String(s.outbox)), h('dt', {}, 'Dropped (queue full)'), h('dd', {}, String(s.dropped)), h('dt', {}, 'Signed commands'), h('dd', {}, s.commands_enabled ? 'Verified and enforced' : 'Off: no pinned command key'), h('dt', {}, 'Last command'), h('dd', {}, timeAgo(s.last_command))),
      s.last_error ? alertBox('error', 'Last send failed: ' + s.last_error) : null, s.command_error ? alertBox('warn', 'Command poll: ' + s.command_error) : null)),
    h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Blocked addresses')), s.deny.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'table' }, h('thead', {}, h('tr', {}, ['Address', 'Until', 'Reason'].map((x) => h('th', {}, x)))),
      h('tbody', {}, s.deny.map((d) => h('tr', {}, h('td', {}, h('span', { class: 'mono' }, d.ip)), h('td', {}, fmtDateTime(d.until)), h('td', { class: 'muted' }, d.reason)))))) : h('div', { class: 'card-body muted' }, 'No addresses are blocked. SkyNet can block an address for you when it detects an attack.')))
}
