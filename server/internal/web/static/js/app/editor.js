// Create and edit items. The form is generated from the field specs in core/item.js.
import { h, icon, toast } from './dom.js'
import { href, navigate } from './router.js'
import { vault, saveItem, getEntry, canWrite, folders, spaceName, newItem, PERSONAL, TYPES, UserError } from './vault.js'
import { MATCH_MODES } from '../core/item.js'
import { parseTotp } from '../core/totp.js'
import { generatorPanel } from './generator.js'
import { strengthMeter, pageHead } from './components.js'
import { alertBox, confirmDialog } from './dialog.js'
import { ApiError } from './api.js'

export function editorView(ctx, { mode, id, type, vaultId }) {
  let entry = null
  let item
  if (mode === 'edit') {
    entry = getEntry(id)
    if (!entry?.item) throw new UserError('That item is not available.')
    if (!canWrite(entry.vaultId)) throw new UserError('You can only read items in this space.')
    item = structuredClone(entry.item)
  } else {
    item = newItem(TYPES[type] ? type : 'login')
  }
  let vaultSel = entry ? entry.vaultId : vaultId && vault.spaces.get(vaultId) && canWrite(vaultId) ? vaultId : PERSONAL
  let dirty = false
  const touch = () => { dirty = true }
  const t = () => TYPES[item.type]

  const form = h('form', { class: 'stack', novalidate: true })
  const err = h('div', { 'aria-live': 'polite' })
  const body = h('div', { class: 'stack' })

  const text = (id, label, value, set, { type = 'text', autocomplete = 'off', hint, placeholder, mono = false } = {}) => {
    const input = h('input', { class: 'input' + (mono ? ' mono' : ''), id, type, value: value ?? '', autocomplete, placeholder, spellcheck: 'false', on: { input: (e) => { set(e.target.value); touch() } } })
    return { input, el: h('div', { class: 'field' }, h('label', { class: 'label', for: id }, label), input, hint ? h('span', { class: 'hint' }, hint) : null) }
  }

  function secretField(f) {
    // type=text with a CSS mask: a real password field makes Chrome offer to save API keys and card numbers in the browser's own
    // (cloud-synced) password manager when the form is "submitted"
    const input = h('input', { class: 'input mono masked', id: 'f-' + f.key, type: 'text', value: item.data[f.key] ?? '', autocomplete: 'off', spellcheck: 'false', 'data-lpignore': 'true', 'data-1p-ignore': 'true', 'data-bwignore': 'true', on: { input: (e) => { item.data[f.key] = e.target.value; touch(); meter?.update() } } })
    const eye = h('button', { class: 'btn btn-icon', type: 'button', 'aria-label': 'Show ' + f.label.toLowerCase(), 'aria-pressed': 'false', on: { click: () => { const show = input.classList.contains('masked'); input.classList.toggle('masked', !show); eye.setAttribute('aria-pressed', String(show)); eye.replaceChildren(icon(show ? 'eye-off' : 'eye')) } } }, icon('eye'))
    const pop = h('div', { class: 'popover hidden', role: 'dialog', 'aria-label': 'Password generator' })
    const genBtn = f.generator ? h('button', { class: 'btn btn-icon', type: 'button', 'aria-label': 'Generate a password', 'aria-expanded': 'false', title: 'Generate', on: { click: () => {
      const open = pop.classList.toggle('hidden') === false
      genBtn.setAttribute('aria-expanded', String(open))
      if (open) { pop.replaceChildren(generatorPanel({ onUse: (pw) => { input.value = pw; item.data[f.key] = pw; input.classList.remove('masked'); touch(); meter?.update(); pop.classList.add('hidden'); genBtn.setAttribute('aria-expanded', 'false'); input.focus() } }).el) }
    } } }, icon('wand')) : null
    const meter = item.type === 'login' && f.key === 'password' ? strengthMeter(() => input.value) : null
    return h('div', { class: 'field' }, h('label', { class: 'label', for: 'f-' + f.key }, f.label), h('div', { class: 'pop' }, h('div', { class: 'input-group' }, input, eye, genBtn), pop), meter?.el)
  }

  function urlsEditor() {
    const wrap = h('div', {})
    const draw = () => {
      wrap.replaceChildren(...item.urls.map((u, i) => h('div', { class: 'url-row' },
        h('input', { class: 'input', 'aria-label': 'Website address ' + (i + 1), value: u.url, placeholder: 'https://example.com', autocomplete: 'off', spellcheck: 'false', on: { input: (e) => { u.url = e.target.value; touch() } } }),
        h('select', { class: 'input', 'aria-label': 'Where to offer it', on: { change: (e) => { u.match = e.target.value; touch() } } }, ...Object.entries(MATCH_MODES).map(([k, l]) => h('option', { value: k, selected: u.match === k }, l))),
        h('button', { class: 'btn btn-ghost btn-icon', type: 'button', 'aria-label': 'Remove address', on: { click: () => { item.urls.splice(i, 1); touch(); draw() } } }, icon('x')))),
      h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => { item.urls.push({ url: '', match: 'host' }); touch(); draw(); wrap.querySelectorAll('.url-row input.input').item(item.urls.length - 1)?.focus() } } }, icon('plus', 'icon-sm'), 'Add website'))
    }
    draw()
    return h('div', { class: 'field' }, h('span', { class: 'label' }, 'Websites'), wrap, h('span', { class: 'hint' }, 'The extension offers this login only on matching websites. “Same host only” is the safest choice.'))
  }

  function customEditor() {
    const wrap = h('div', {})
    const draw = () => wrap.replaceChildren(...item.custom.map((c, i) => h('div', { class: 'cf-row' },
      h('input', { class: 'input', 'aria-label': 'Field name', spellcheck: 'false', value: c.label, placeholder: 'Name', on: { input: (e) => { c.label = e.target.value; touch() } } }),
      h('input', { class: 'input' + (c.hidden ? ' masked' : ''), 'aria-label': 'Field value', type: 'text', value: c.value, placeholder: 'Value', autocomplete: 'off', spellcheck: 'false', 'data-lpignore': 'true', 'data-1p-ignore': 'true', on: { input: (e) => { c.value = e.target.value; touch() } } }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: c.hidden, on: { change: (e) => { c.hidden = e.target.checked; touch(); draw() } } }), 'Hide'),
      h('button', { class: 'btn btn-ghost btn-icon', type: 'button', 'aria-label': 'Remove field', on: { click: () => { item.custom.splice(i, 1); touch(); draw() } } }, icon('x')))),
    h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => { item.custom.push({ label: '', value: '', hidden: false }); touch(); draw() } } }, icon('plus', 'icon-sm'), 'Add custom field'))
    draw()
    return h('div', { class: 'field' }, h('span', { class: 'label' }, 'Custom fields'), wrap)
  }

  const build = () => {
    const parts = []
    const name = text('f-name', 'Name', item.name, (v) => { item.name = v }, { autocomplete: 'off' })
    parts.push(name.el)
    if (mode === 'new') {
      parts.push(h('div', { class: 'field' }, h('label', { class: 'label', for: 'f-type' }, 'Type'), h('select', { class: 'input', id: 'f-type', on: { change: (e) => { item = Object.assign(newItem(e.target.value), { name: item.name, folder: item.folder, notes: item.notes, urls: item.urls, tags: item.tags, fav: item.fav }); build(); } } },
        ...Object.entries(TYPES).map(([k, v]) => h('option', { value: k, selected: item.type === k }, v.label)))))
    }
    for (const f of t().fields) {
      if (f.kind === 'secret') parts.push(secretField(f))
      else if (f.kind === 'multiline-secret') parts.push(h('div', { class: 'field' }, h('label', { class: 'label', for: 'f-' + f.key }, f.label), h('textarea', { class: 'input mono', id: 'f-' + f.key, rows: 5, spellcheck: 'false', autocomplete: 'off', value: item.data[f.key] ?? '', on: { input: (e) => { item.data[f.key] = e.target.value; touch() } } })))
      else if (f.kind === 'totp') parts.push(text('f-' + f.key, f.label, item.data[f.key], (v) => { item.data[f.key] = v }, { mono: true, hint: 'Paste the secret key or the full otpauth:// link from the site’s 2-step setup page.' }).el)
      else if (f.kind === 'date') parts.push(text('f-' + f.key, f.label, item.data[f.key], (v) => { item.data[f.key] = v }, { type: 'date' }).el)
      else parts.push(text('f-' + f.key, f.label, item.data[f.key], (v) => { item.data[f.key] = v }, { placeholder: f.placeholder, autocomplete: f.key === 'username' ? 'off' : 'off' }).el)
    }
    if (t().urls) parts.push(urlsEditor())
    parts.push(h('div', { class: 'field' }, h('label', { class: 'label', for: 'f-notes' }, 'Notes'), h('textarea', { class: 'input', id: 'f-notes', rows: 4, spellcheck: 'false', value: item.notes, on: { input: (e) => { item.notes = e.target.value; touch() } } })))
    parts.push(customEditor())
    const fl = folders().map(([n]) => n)
    parts.push(h('div', { class: 'row' },
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'f-folder' }, 'Folder'), h('input', { class: 'input', id: 'f-folder', value: item.folder, list: 'folder-list', autocomplete: 'off', placeholder: 'Optional', on: { input: (e) => { item.folder = e.target.value; touch() } } }), h('datalist', { id: 'folder-list' }, fl.map((n) => h('option', { value: n })))),
      h('div', { class: 'field' }, h('label', { class: 'label', for: 'f-tags' }, 'Tags'), h('input', { class: 'input', id: 'f-tags', value: item.tags.join(', '), autocomplete: 'off', placeholder: 'comma, separated', on: { input: (e) => { item.tags = e.target.value.split(',').map((s) => s.trim()).filter(Boolean); touch() } } }))))
    if (mode === 'new') {
      const writable = [...vault.spaces.values()].filter((s) => canWrite(s.id) && s.key)
      if (writable.length) {
        parts.push(h('div', { class: 'field' }, h('label', { class: 'label', for: 'f-vault' }, 'Save to'), h('select', { class: 'input', id: 'f-vault', on: { change: (e) => { vaultSel = e.target.value } } },
          h('option', { value: PERSONAL, selected: vaultSel === PERSONAL }, 'Personal (only you)'), ...writable.map((s) => h('option', { value: s.id, selected: vaultSel === s.id }, `Space: ${s.name} (shared)`)))))
      }
    } else if (entry.vaultId !== PERSONAL) parts.push(h('p', { class: 'muted small' }, icon('users', 'icon-sm'), ' Shared in the space “', spaceName(entry.vaultId), '”.'))
    parts.push(h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: item.fav, on: { change: (e) => { item.fav = e.target.checked; touch() } } }), 'Favorite'))
    body.replaceChildren(...parts)
  }
  build()

  const save = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Save')
  const cancel = h('button', { class: 'btn', type: 'button', on: { click: async () => {
    if (dirty && !(await confirmDialog({ title: 'Discard changes?', body: 'You have unsaved changes.', confirm: 'Discard', danger: true }))) return
    navigate(entry ? '/all/item/' + entry.id : '/all')
  } } }, 'Cancel')
  form.append(body, err, h('div', { class: 'form-actions' }, save, cancel))
  form.addEventListener('submit', async (e) => {
    e.preventDefault()
    if (!item.name.trim()) { err.replaceChildren(alertBox('error', 'Give the item a name.')); document.getElementById('f-name')?.focus(); return }
    if (item.data.totp) { try { parseTotp(item.data.totp) } catch (x) { err.replaceChildren(alertBox('error', x.message)); document.getElementById('f-totp')?.focus(); return } }
    item.urls = item.urls.filter((u) => u.url.trim())
    save.disabled = true
    try {
      const saved = await saveItem({ id: entry?.id, vaultId: vaultSel, item })
      dirty = false
      toast(mode === 'new' ? 'Item saved' : 'Changes saved')
      navigate('/all/item/' + saved.id)
    } catch (x) {
      save.disabled = false
      err.replaceChildren(alertBox('error', x instanceof ApiError && x.code === 'conflict' ? 'This item was changed on another device. Reload it to see the latest version, then re-apply your edit.' : x.message))
    }
  })
  const warn = (e) => { if (dirty) { e.preventDefault(); e.returnValue = '' } }
  window.addEventListener('beforeunload', warn)
  ctx.onCleanup(() => window.removeEventListener('beforeunload', warn))
  setTimeout(() => document.getElementById('f-name')?.focus(), 0)

  return h('div', { class: 'stack', 'aria-label': mode === 'new' ? 'New item' : 'Edit item' },
    h('div', { class: 'breadcrumb' }, h('a', { href: href(entry ? '/all/item/' + entry.id : '/all') }, icon('arrow-left', 'icon-sm'), ' Back')),
    pageHead(mode === 'new' ? 'New item' : 'Edit item'),
    h('div', { class: 'card' }, h('div', { class: 'card-body' }, form)))
}
