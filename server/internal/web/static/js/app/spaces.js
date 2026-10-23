// Spaces: shared vaults for a team. Members, roles, key rotation, fingerprints.
import { h, icon, toast, avatarClass, initials, debounce, mount } from './dom.js'
import { href, navigate } from './router.js'
import { vault, createSpace, renameSpace, deleteSpace, addMember, setMemberRole, removeMember, rotateSpace, searchDirectory, memberFingerprint, pinnedFingerprint, pinFingerprint, live } from './vault.js'
import { pageHead, emptyState, spinner } from './components.js'
import { confirmDialog, modal, alertBox } from './dialog.js'
import { fingerprint } from '../core/keys.js'

const ROLES = { owner: 'Owner: manages members and the key', editor: 'Editor: can add and change items', viewer: 'Viewer: read-only' }

function nameDialog(title, initial = '') {
  const input = h('input', { class: 'input', id: 'sp-name', value: initial, maxlength: 80, autocomplete: 'off', required: true })
  return modal({ title, body: h('div', { class: 'field' }, h('label', { class: 'label', for: 'sp-name' }, 'Name'), input),
    actions: (done) => { const go = () => input.value.trim() && done(input.value.trim()); input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); go() } })
      return [h('button', { class: 'btn', type: 'button', on: { click: () => done(null) } }, 'Cancel'), h('button', { class: 'btn btn-primary', type: 'button', on: { click: go } }, 'Save')] } }).then((v) => v ?? null)
}

export function spaceManageView(ctx) {
  const id = ctx.route.seg[1]
  if (!id) return spacesIndex()
  return spaceDetail(ctx, id)
}

function spacesIndex() {
  const rows = [...vault.spaces.values()]
  return h('div', {}, pageHead('Spaces', 'A space is a shared vault. Items in it are encrypted with a key that only its members hold.',
    h('button', { class: 'btn btn-primary', type: 'button', on: { click: async () => { const n = await nameDialog('New space'); if (!n) return; try { const sid = await createSpace(n); toast('Space created'); navigate('/space-manage/' + sid) } catch (e) { toast(e.message, 'error') } } } }, icon('plus'), 'New space')),
  rows.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'table table-stack' }, h('thead', {}, h('tr', {}, ['Space', 'Your role', 'Members', 'Items', ''].map((x) => h('th', {}, x)))),
    h('tbody', {}, rows.map((s) => h('tr', {}, h('td', { 'data-label': 'Space' }, h('a', { href: href('/space/' + s.id) }, s.name), s.needsRotation ? h('span', { class: 'badge badge-warn' }, 'Rotate key') : null, s.warning ? h('span', { class: 'badge badge-danger' }, 'Problem') : null),
      h('td', { 'data-label': 'Your role' }, s.role), h('td', { 'data-label': 'Members' }, String(s.members.length)), h('td', { 'data-label': 'Items' }, String(live().filter((e) => e.vaultId === s.id).length)),
      h('td', {}, h('a', { class: 'btn btn-sm', href: href('/space-manage/' + s.id) }, 'Manage'))))))) : emptyState('users', 'No spaces yet', 'Create a space to share logins and API keys with your team.'))
}

async function spaceDetail(ctx, id) {
  const sp = vault.spaces.get(id)
  if (!sp) return emptyState('alert', 'Space not found', 'You may have been removed from it.', h('a', { class: 'btn', href: href('/spaces') }, 'All spaces'))
  const owner = sp.role === 'owner'
  const box = h('div', { class: 'stack' })
  const fps = new Map()
  for (const m of sp.members) fps.set(m.sub, await memberFingerprint(m))

  const run = async (fn, ok) => { try { await fn(); if (ok) toast(ok); ctx.refreshSide(); navigate('/space-manage/' + id, undefined, {}) } catch (e) { toast(e.message, 'error') } }
  const render = () => {
    const parts = []
    if (sp.warning) parts.push(alertBox('error', sp.warning))
    if (sp.needsRotation && owner) {
      const btn = h('button', { class: 'btn btn-primary btn-sm', type: 'button' }, 'Rotate key now')
      btn.addEventListener('click', async () => {
        btn.disabled = true; btn.replaceChildren(h('span', { class: 'spin' }), 'Re-encrypting…')
        try { await rotateSpace(id); toast('Key rotated'); navigate('/space-manage/' + id) } catch (e) { toast(e.message, 'error'); btn.disabled = false; btn.replaceChildren('Rotate key now') }
      })
      parts.push(h('div', { class: 'alert alert-warn' }, icon('alert'), h('div', {}, h('strong', {}, 'The key must be rotated. '), 'Someone left or was removed, and they still know the current key. Rotating re-encrypts every item in this space with a new key and gives it only to the remaining members. Until then, new members cannot be added.', h('div', { class: 'cluster' }, btn))))
    } else if (sp.needsRotation) parts.push(alertBox('warn', 'A member left. An owner needs to rotate the key.'))

    parts.push(h('div', { class: 'card' },
      h('div', { class: 'card-head' }, h('h2', {}, 'Members'), owner ? h('button', { class: 'btn btn-sm btn-primary', type: 'button', disabled: sp.needsRotation, on: { click: () => addDialog(id, fps, () => navigate('/space-manage/' + id)) } }, icon('plus', 'icon-sm'), 'Add member') : null),
      h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Space members' }, h('table', { class: 'table table-stack' }, h('thead', {}, h('tr', {}, ['Person', 'Role', 'Fingerprint', ''].map((x) => h('th', {}, x)))),
        h('tbody', {}, sp.members.map((m) => {
          const me = m.sub === vault.me.sub
          const pinned = pinnedFingerprint(m.sub)
          const changed = pinned && pinned !== fps.get(m.sub)
          return h('tr', {},
            h('td', { 'data-label': 'Person' }, h('div', { class: 'cluster' }, h('span', { class: `avatar avatar-sm ${avatarClass(m.sub)}` }, initials(m.name || m.email)), h('div', {}, h('strong', {}, m.name || m.email, me ? ' (you)' : ''), h('div', { class: 'muted small' }, m.email)))),
            h('td', { 'data-label': 'Role' }, owner && !me ? h('select', { class: 'input', 'aria-label': 'Role of ' + (m.name || m.email), on: { change: (e) => run(() => setMemberRole(id, m.sub, e.target.value), 'Role updated') } }, ...Object.keys(ROLES).map((r) => h('option', { value: r, selected: m.role === r }, r))) : h('span', { class: 'badge' }, m.role)),
            h('td', { 'data-label': 'Fingerprint' }, h('details', {}, h('summary', {}, changed ? h('span', { class: 'badge badge-danger' }, 'Changed!') : pinned ? h('span', { class: 'badge badge-ok' }, icon('check', 'icon-sm'), 'Pinned') : 'Show'), h('div', { class: 'fp' }, fps.get(m.sub)), h('p', { class: 'hint' }, 'Compare this with the person, in person or by phone. If it differs, do not trust their access.'), changed ? h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => { pinFingerprint(m.sub, fps.get(m.sub)); toast('New fingerprint accepted'); navigate('/space-manage/' + id) } } }, 'Accept the new fingerprint') : null)),
            h('td', {}, (owner && !me) || me ? h('button', { class: 'btn btn-sm btn-ghost', type: 'button', on: { click: async () => {
              const leaving = me
              if (await confirmDialog({ title: leaving ? 'Leave this space?' : `Remove ${m.name || m.email}?`, body: leaving ? 'You will lose access to its items.' : 'They lose access at once. You will then rotate the key so they cannot read future changes.', confirm: leaving ? 'Leave' : 'Remove', danger: true })) {
                try { await removeMember(id, m.sub); toast(leaving ? 'You left the space' : 'Member removed'); navigate(leaving ? '/spaces' : '/space-manage/' + id) } catch (e) { toast(e.message, 'error') }
              }
            } } }, leaving(me)) : null))
        }))))))
    if (owner) {
      parts.push(h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, 'Space settings')),
        h('div', { class: 'card-body cluster' },
          h('button', { class: 'btn', type: 'button', on: { click: async () => { const n = await nameDialog('Rename space', sp.name); if (n) run(() => renameSpace(id, n), 'Renamed') } } }, icon('edit', 'icon-sm'), 'Rename'),
          h('button', { class: 'btn', type: 'button', on: { click: async () => { if (await confirmDialog({ title: 'Rotate the space key?', body: 'Every item is re-encrypted with a new key. It takes a moment for large spaces.', confirm: 'Rotate' })) { try { await rotateSpace(id); toast('Key rotated'); navigate('/space-manage/' + id) } catch (e) { toast(e.message, 'error') } } } } }, icon('refresh', 'icon-sm'), 'Rotate key')),
        h('div', { class: 'card-foot' }, h('button', { class: 'btn btn-danger btn-sm', type: 'button', on: { click: async () => { if (await confirmDialog({ title: `Delete “${sp.name}”?`, body: 'Every item in the space is deleted for all members. This cannot be undone.', confirm: 'Delete space', danger: true })) { try { await deleteSpace(id); toast('Space deleted'); navigate('/spaces') } catch (e) { toast(e.message, 'error') } } } } }, icon('trash', 'icon-sm'), 'Delete space'))))
    }
    mount(box, ...parts)
  }
  render()
  return h('div', {}, h('div', { class: 'breadcrumb' }, h('a', { href: href('/spaces') }, 'Spaces'), ' / ', sp.name), pageHead(sp.name, `${sp.members.length} member${sp.members.length === 1 ? '' : 's'} · you are ${sp.role === 'owner' ? 'an owner' : 'a ' + sp.role}`, h('a', { class: 'btn', href: href('/space/' + id) }, icon('vault'), 'Open items')), box)
}

const leaving = (me) => (me ? 'Leave' : 'Remove')

function addDialog(spaceId, fps, done) {
  const q = h('input', { class: 'input', id: 'dir-q', type: 'search', placeholder: 'Name or email', autocomplete: 'off' })
  const results = h('div', { class: 'stack-sm', 'aria-live': 'polite' })
  const role = h('select', { class: 'input', id: 'dir-role' }, ...Object.entries(ROLES).filter(([r]) => r !== 'owner' || true).map(([r, l]) => h('option', { value: r, selected: r === 'editor' }, l)))
  const search = debounce(async () => {
    if (q.value.trim().length < 2) { mount(results, h('p', { class: 'muted small' }, 'Type at least two letters. Only people who have set up their vault can be added.')); return }
    mount(results, spinner('Searching'))
    try {
      const us = await searchDirectory(q.value.trim())
      const members = new Set(vault.spaces.get(spaceId).members.map((m) => m.sub))
      mount(results, us.length ? us.map((u) => h('div', { class: 'cluster' }, h('span', { class: `avatar avatar-sm ${avatarClass(u.sub)}` }, initials(u.name || u.email)), h('div', {}, h('strong', {}, u.name || u.email), h('div', { class: 'muted small' }, u.email)), h('span', { class: 'spacer' }),
        members.has(u.sub) ? h('span', { class: 'badge' }, 'Member') : h('button', { class: 'btn btn-sm btn-primary', type: 'button', on: { click: () => confirmAdd(u) } }, 'Add'))) : h('p', { class: 'muted small' }, 'No one found. They need to sign in to TheVault and create their vault first.'))
    } catch (e) { mount(results, alertBox('error', e.message)) }
  }, 250)
  q.addEventListener('input', search)
  let dlgDone
  async function confirmAdd(u) {
    const fp = await fingerprint(u.enc_pub, u.sig_pub)
    const ok = await confirmDialog({ title: `Add ${u.name || u.email}?`, body: h('div', { class: 'stack-sm' }, h('p', {}, `They will be able to ${role.value === 'viewer' ? 'read' : role.value === 'editor' ? 'read and change' : 'manage'} everything in this space.`),
      h('p', { class: 'small muted' }, 'Their key fingerprint (confirm it with them if the space is sensitive):'), h('div', { class: 'fp' }, fp)), confirm: 'Add member' })
    if (!ok) return
    try { await addMember(spaceId, u, role.value); toast('Member added'); dlgDone?.(true); done() } catch (e) { toast(e.message, 'error') }
  }
  return modal({ title: 'Add a member', body: h('div', { class: 'stack' }, h('div', { class: 'field' }, h('label', { class: 'label', for: 'dir-q' }, 'Find a person'), q), h('div', { class: 'field' }, h('label', { class: 'label', for: 'dir-role' }, 'Role'), role), results),
    actions: (d) => { dlgDone = d; return [h('button', { class: 'btn', type: 'button', on: { click: () => d(false) } }, 'Close')] } })
}
