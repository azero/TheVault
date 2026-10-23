// The vault: item list (left) and the selected item (right). On phones only one of them is shown at a time.
import { h, icon, toast, timeAgo, fmtDateTime } from './dom.js'
import { href, navigate } from './router.js'
import { vault, list, getEntry, canWrite, spaceName, toggleFavourite, trashItem, restoreItem, purgeItem, emptyTrash, moveItem, itemVersions, saveItem, live, PERSONAL, TYPES } from './vault.js'
import { itemAvatar, fieldRow, totpRow, typeBadge, emptyState, iconButton, strengthMeter } from './components.js'
import { confirmDialog, modal, alertBox } from './dialog.js'
import { MATCH_MODES } from '../core/item.js'
import { copy } from './clipboard.js'
import { sha256 } from '../core/crypto.js'
import { utf8, b64uEncode } from '../core/b64.js'
import { parseUrl } from '../core/urlmatch.js'

const SCOPES = ['all', 'fav', 'type', 'folder', 'space', 'trash']

// A member can share an item with any text in the address field: show it without bidi/control characters, and link to the
// address as the browser will parse it (userinfo tricks such as https://good.com\@evil.com resolve to what they really are).
function siteLink(raw) {
  const shown = String(raw).replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, '')
  let url
  try { url = new URL(/^https?:\/\//i.test(shown) ? shown : 'https://' + shown) } catch { return h('span', {}, shown) }
  if (url.username || url.password) return h('span', {}, shown, ' ', h('span', { class: 'badge badge-danger' }, 'Contains a login: not linked'))
  return h('a', { href: url.href, target: '_blank', rel: 'noopener noreferrer' }, shown)
}

export function scopeOf(route) {
  const [a, b] = route.seg
  if (!a || a === 'all') return { kind: 'all', title: 'All items' }
  if (a === 'fav') return { kind: 'fav', title: 'Favorites' }
  if (a === 'trash') return { kind: 'trash', title: 'Trash' }
  if (a === 'type' && TYPES[b]) return { kind: 'type', value: b, title: TYPES[b].plural }
  if (a === 'folder') return { kind: 'folder', value: b, title: b }
  if (a === 'space') return { kind: 'space', value: b, title: spaceName(b) }
  return { kind: 'all', title: 'All items' }
}

function subtitle(it) {
  const d = it.data
  switch (it.type) {
    case 'login': return d.username || hostOf(it)
    case 'api_key': return [d.service, d.env].filter(Boolean).join(' · ') || hostOf(it)
    case 'server': return [d.username, d.host].filter(Boolean).join('@')
    case 'card': return d.number ? '•••• ' + d.number.replace(/\D/g, '').slice(-4) : 'Card'
    default: return 'Secure note'
  }
}
const hostOf = (it) => parseUrl(it.urls[0]?.url)?.host ?? ''

export function listView(ctx, ui) {
  const { route } = ctx
  const scope = scopeOf(route)
  const rows = list(scope, ui.query, ui.sort)
  const base = route.path
  const q = ui.query ? { q: ui.query } : undefined

  const sort = h('select', { class: 'input', 'aria-label': 'Sort', on: { change: (e) => { ui.sort = e.target.value; navigate(base, undefined, { replace: true }) } } },
    ...[['name', 'Name'], ['recent', 'Recently changed'], ['created', 'Newest']].map(([v, l]) => h('option', { value: v, selected: ui.sort === v }, l)))
  sort.classList.add('sort')

  const headExtras = []
  if (scope.kind === 'trash' && rows.length) {
    headExtras.push(h('button', { class: 'btn btn-sm btn-danger', type: 'button', on: { click: async () => {
      if (await confirmDialog({ title: 'Empty the trash?', body: 'Every item in the trash is deleted for good. This cannot be undone.', confirm: 'Delete forever', danger: true })) {
        const n = await emptyTrash(); toast(`${n} item${n === 1 ? '' : 's'} deleted`); navigate(base)
      }
    } } }, 'Empty'))
  }
  if (scope.kind === 'space' && canWrite(scope.value)) headExtras.push(h('a', { class: 'btn btn-sm', href: href('/new/login', { vault: scope.value }) }, icon('plus', 'icon-sm'), 'Add'))
  if (scope.kind === 'space') headExtras.push(h('a', { class: 'btn btn-ghost btn-icon btn-sm', href: href('/space-manage/' + scope.value), title: 'Manage space', 'aria-label': 'Manage space' }, icon('settings')))
  if (scope.kind === 'type') headExtras.push(h('a', { class: 'btn btn-sm', href: href('/new/' + scope.value) }, icon('plus', 'icon-sm'), 'Add'))

  const sp = scope.kind === 'space' ? vault.spaces.get(scope.value) : null
  const banners = []
  if (sp?.needsRotation) banners.push(h('div', { class: 'alert alert-warn' }, icon('alert'), h('div', {}, h('strong', {}, 'A member was removed. '), 'Rotate the key so they cannot read new changes. ', h('a', { href: href('/space-manage/' + sp.id) }, 'Rotate now'))))
  if (sp?.warning) banners.push(alertBox('error', sp.warning))

  const items = h('ul', { class: 'items', role: 'list' }, rows.map((e) => {
    const it = e.item
    const cur = route.itemId === e.id
    return h('li', {}, h('a', { class: 'item-row', href: href(base + '/item/' + e.id, q), 'aria-current': cur ? 'true' : null },
      itemAvatar(it),
      h('span', { class: 'meta' }, h('span', { class: 'title truncate' }, it.name || '(untitled)', it.fav ? h('span', { class: 'fav' }, icon('star', 'icon-sm filled')) : null), h('span', { class: 'sub truncate' }, subtitle(it))),
      e.vaultId !== PERSONAL ? h('span', { class: 'badge badge-gold', title: spaceName(e.vaultId) }, icon('users', 'icon-sm')) : null,
      it.data.totp ? h('span', { class: 'badge', title: 'Has a one-time password' }, icon('clock', 'icon-sm')) : null))
  }))

  const empty = scope.kind === 'trash'
    ? emptyState('trash', 'The trash is empty', 'Deleted items stay here for 30 days.')
    : ui.query ? emptyState('search', 'Nothing matches', `No items match “${ui.query}”.`)
      : live().length === 0 ? emptyState('vault', 'Your vault is empty', 'Add your first login, API key or note, or import from another password manager.', h('div', { class: 'cluster' }, h('a', { class: 'btn btn-primary', href: href('/new/login') }, icon('plus'), 'Add an item'), h('a', { class: 'btn', href: href('/settings/data') }, icon('upload'), 'Import')))
        : emptyState('folder', 'No items here yet', 'Items you add to this view appear here.')

  const listPane = h('section', { class: 'list-pane', 'aria-label': 'Items' },
    h('div', { class: 'list-head' }, h('div', { class: 'truncate' }, h('h1', { class: 'truncate' }, scope.title), h('div', { class: 'sub' }, `${rows.length} item${rows.length === 1 ? '' : 's'}`)), h('span', { class: 'spacer' }), ...headExtras, rows.length > 1 ? sort : null),
    ...banners.map((b) => h('div', { class: 'content' }, b)),
    rows.length ? items : empty)

  const entry = route.itemId ? getEntry(route.itemId) : null
  let detail
  if (entry) detail = detailView(ctx, entry, scope)
  else if (route.itemId) detail = emptyState('alert', 'Item not found', 'It may have been deleted on another device.', h('a', { class: 'btn', href: href(base) }, 'Back to the list'))
  else detail = h('div', { class: 'detail-empty' }, emptyState('shield', 'Select an item', 'Everything here is encrypted on your device.'))

  return h('div', { class: 'panes' + (route.itemId ? ' show-detail' : '') }, listPane, h('section', { class: 'detail-pane', 'aria-label': 'Item details' }, detail))
}

// ---------- detail ----------

function detailView(ctx, e, scope) {
  const { route } = ctx
  const back = route.path
  const wrap = h('div', { class: 'detail' })
  const backLink = h('a', { class: 'btn btn-ghost btn-sm no-print', href: href(back, route.query.q ? { q: route.query.q } : undefined) }, icon('arrow-left'), 'Back')
  backLink.classList.add('mobile-only')
  if (e.error || !e.item) {
    wrap.append(alertBox('error', e.error || 'This item could not be opened.'))
    return wrap
  }
  const it = e.item
  const t = TYPES[it.type]
  const writable = canWrite(e.vaultId)
  const inTrash = !!e.deletedAt

  const actions = h('div', { class: 'cluster no-print' })
  if (inTrash) {
    if (writable) {
      actions.append(h('button', { class: 'btn btn-primary btn-sm', type: 'button', on: { click: async () => { await restoreItem(e.id); toast('Restored'); navigate('/all/item/' + e.id) } } }, icon('refresh', 'icon-sm'), 'Restore'))
      actions.append(h('button', { class: 'btn btn-danger btn-sm', type: 'button', on: { click: async () => {
        if (await confirmDialog({ title: 'Delete forever?', body: `“${it.name}” will be permanently deleted.`, confirm: 'Delete forever', danger: true })) { await purgeItem(e.id); toast('Deleted'); navigate(back) }
      } } }, icon('trash', 'icon-sm'), 'Delete forever'))
    }
  } else if (writable) {
    actions.append(
      h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: it.fav ? 'Remove from favorites' : 'Add to favorites', 'aria-label': it.fav ? 'Remove from favorites' : 'Add to favorites', 'aria-pressed': String(it.fav), on: { click: async () => { await toggleFavourite(e.id); navigate(route.path + (route.itemId ? '/item/' + e.id : ''), route.query.q ? { q: route.query.q } : undefined) } } }, icon('star', it.fav ? 'filled' : '')),
      h('a', { class: 'btn btn-sm', href: href('/edit/' + e.id) }, icon('edit', 'icon-sm'), 'Edit'),
      h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: 'Move to…', 'aria-label': 'Move to another vault', on: { click: () => moveDialog(e) } }, icon('layers')),
      h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', title: 'Move to trash', 'aria-label': 'Move to trash', on: { click: async () => { await trashItem(e.id); toast('Moved to trash'); navigate(back) } } }, icon('trash')))
  } else actions.append(h('span', { class: 'badge' }, icon('lock', 'icon-sm'), 'Read-only'))

  wrap.append(backLink, h('div', { class: 'detail-head' }, itemAvatar(it, 'avatar-lg'),
    h('div', { class: 'titles' }, h('h1', {}, it.name || '(untitled)'),
      h('div', { class: 'sub' }, typeBadge(it.type), e.vaultId !== PERSONAL ? h('span', { class: 'badge badge-gold' }, icon('users', 'icon-sm'), spaceName(e.vaultId)) : null, inTrash ? h('span', { class: 'badge badge-warn' }, 'In trash') : null, it.folder ? h('span', { class: 'badge' }, icon('folder', 'icon-sm'), it.folder) : null)),
    actions))

  const fields = h('div', { class: 'fields' })
  const stops = []
  for (const f of t.fields) {
    const v = it.data[f.key]
    if (!v) continue
    if (f.kind === 'totp') { const r = totpRow(v); stops.push(r.stop); fields.append(r.el); continue }
    const row = fieldRow({ label: f.label.replace(/ \(.*\)$/, ''), value: v, secret: f.kind === 'secret' || f.kind === 'multiline-secret', mono: f.key === 'number' || f.kind === 'multiline-secret', pre: f.kind === 'multiline-secret' })
    if (row) fields.append(row)
    if (f.key === t.main && it.type === 'login') {
      const m = strengthMeter(() => v)
      row.querySelector('.body').append(h('div', { class: 'strength' }, m.el))
      reuseBadge(e, row)
    }
  }
  for (const c of it.custom) fields.append(fieldRow({ label: c.label || 'Field', value: c.value, secret: c.hidden }))
  if (it.urls.length) {
    fields.append(h('div', { class: 'fld' }, h('div', { class: 'body' }, h('div', { class: 'k' }, it.urls.length > 1 ? 'Websites' : 'Website'),
      ...it.urls.map((u) => h('div', { class: 'v' }, siteLink(u.url), ' ', h('span', { class: 'badge' }, MATCH_MODES[u.match] ?? '')))), h('div', { class: 'acts' })))
  }
  if (it.notes) fields.append(fieldRow({ label: 'Notes', value: it.notes, pre: true, copyLabel: undefined }))
  if (fields.children.length) wrap.append(h('div', { class: 'card' }, fields))
  else wrap.append(h('div', { class: 'card' }, h('div', { class: 'card-body muted' }, 'This item has no saved details yet.')))
  ctx.onCleanup(() => stops.forEach((f) => f()))

  if (it.tags.length) wrap.append(h('div', { class: 'cluster' }, ...it.tags.map((tg) => h('span', { class: 'badge' }, icon('tag', 'icon-sm'), tg))))

  if (it.history.length) {
    wrap.append(h('h2', { class: 'section-title' }, 'Previous values'), h('div', { class: 'card' }, h('div', { class: 'fields' },
      ...it.history.map((x) => fieldRow({ label: 'Replaced ' + timeAgo(x.at / 1000), value: x.value, secret: true })))))
  }
  wrap.append(versionsBlock(e), h('p', { class: 'muted small' }, `Created ${fmtDateTime(it.created / 1000)} · Changed ${fmtDateTime(it.updated / 1000)}`))
  return wrap
}

function versionsBlock(e) {
  const box = h('div', { class: 'no-print' })
  const btn = h('button', { class: 'btn btn-ghost btn-sm', type: 'button' }, icon('history', 'icon-sm'), 'Show earlier versions')
  btn.addEventListener('click', async () => {
    btn.disabled = true
    try {
      const vs = await itemVersions(e.id)
      box.replaceChildren(h('h2', { class: 'section-title' }, 'Earlier versions'),
        vs.length ? h('ul', { class: 'history' }, vs.map((v) => h('li', {}, h('span', { class: 'truncate' }, fmtDateTime(v.savedAt), ' · ', v.item.name), h('span', { class: 'spacer' }),
          canWrite(e.vaultId) && !e.deletedAt ? h('button', { class: 'btn btn-sm', type: 'button', on: { click: async () => {
            if (await confirmDialog({ title: 'Restore this version?', body: 'The current version is kept in the history.', confirm: 'Restore' })) { await saveItem({ id: e.id, vaultId: e.vaultId, item: v.item }); toast('Version restored'); navigate(location.hash.replace(/^#/, '').split('?')[0]) }
          } } }, 'Restore') : null))) : h('p', { class: 'muted' }, 'There are no earlier versions.'))
    } catch (err) { toast(err.message, 'error'); btn.disabled = false }
  })
  box.append(btn)
  return box
}

async function reuseBadge(e, row) {
  const main = e.item.data.password
  if (!main) return
  const mine = b64uEncode(await sha256(utf8(main)))
  let n = 0
  for (const o of live()) {
    if (o.id !== e.id && o.item?.type === 'login' && o.item.data.password) if (b64uEncode(await sha256(utf8(o.item.data.password))) === mine) n++
  }
  if (n > 0) row.querySelector('.strength')?.append(h('span', { class: 'badge badge-warn' }, icon('alert', 'icon-sm'), `Also used by ${n} other item${n === 1 ? '' : 's'}`))
}

function moveDialog(e) {
  const sel = h('select', { class: 'input', id: 'mv' }, h('option', { value: PERSONAL, selected: e.vaultId === PERSONAL }, 'Personal'),
    ...[...vault.spaces.values()].filter((s) => canWrite(s.id) && s.key).map((s) => h('option', { value: s.id, selected: e.vaultId === s.id }, s.name)))
  return modal({
    title: 'Move item',
    body: h('div', { class: 'stack' }, h('p', { class: 'muted' }, 'Moving to a space shares the item with everyone in it. Moving it back to Personal stops sharing.'), h('div', { class: 'field' }, h('label', { class: 'label', for: 'mv' }, 'Move to'), sel)),
    actions: (done) => [h('button', { class: 'btn', type: 'button', on: { click: () => done(false) } }, 'Cancel'),
      h('button', { class: 'btn btn-primary', type: 'button', on: { click: async () => {
        try { const moved = await moveItem(e.id, sel.value); done(true); toast('Moved'); navigate('/all/item/' + moved.id) } catch (err) { toast(err.message, 'error') }
      } } }, 'Move')],
  })
}

export { SCOPES }
