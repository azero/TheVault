import { h, icon, avatarClass, initials, ring } from './dom.js'
import { copy } from './clipboard.js'
import { TYPES } from '../core/item.js'
import { estimateStrength } from '../core/strength.js'
import { parseTotp, totpCode, secondsRemaining } from '../core/totp.js'

export function itemAvatar(item, cls = '') {
  const t = TYPES[item.type]
  const useIcon = item.type === 'card' || item.type === 'note' || !item.name
  return h('span', { class: `avatar sq ${avatarClass(item.name || item.type)} ${cls}` }, useIcon ? icon(t.icon) : initials(item.name).slice(0, 2))
}

export function iconButton({ label, icon: ic, onClick, cls = '' }) {
  return h('button', { class: 'btn btn-ghost btn-icon btn-sm ' + cls, type: 'button', title: label, 'aria-label': label, on: { click: onClick } }, icon(ic))
}

export function strengthMeter(getValue) {
  const bar = h('span')
  const wrap = h('div', { class: 'meter', role: 'presentation' }, bar)
  const label = h('span')
  const bits = h('span')
  const box = h('div', { 'aria-live': 'polite' }, wrap, h('div', { class: 'meter-label' }, label, bits))
  const update = (v = getValue()) => {
    const s = estimateStrength(v)
    wrap.dataset.score = v ? String(s.score) : 'none'
    label.textContent = v ? s.label : ''
    bits.textContent = v ? `~${s.bits} bits` : ''
  }
  update()
  return { el: box, update }
}

/** One labelled row in the detail card. */
export function fieldRow({ label, value, secret = false, copyLabel, mono = false, pre = false, href, extra }) {
  if (!value && !extra) return null
  let shown = false
  const v = h('div', { class: 'v' + (mono ? ' mono' : '') + (pre ? ' pre' : '') })
  const draw = () => {
    v.replaceChildren()
    if (secret && !shown) v.append(h('span', { class: 'secret-dots', 'aria-label': 'hidden' }, '•'.repeat(Math.min(14, Math.max(8, value.length)))))
    else if (href) v.append(h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, value))
    else v.append(value ?? '')
  }
  draw()
  const acts = h('div', { class: 'acts' })
  if (secret) {
    const eye = h('button', { class: 'btn btn-ghost btn-icon btn-sm', type: 'button', 'aria-label': `Show ${label.toLowerCase()}`, 'aria-pressed': 'false', title: 'Show or hide' })
    eye.append(icon('eye'))
    eye.addEventListener('click', () => {
      shown = !shown; draw(); eye.setAttribute('aria-pressed', String(shown)); eye.replaceChildren(icon(shown ? 'eye-off' : 'eye'))
    })
    acts.append(eye)
  }
  if (value && copyLabel !== false) acts.append(iconButton({ label: `Copy ${label.toLowerCase()}`, icon: 'copy', onClick: () => copy(value, `${label} copied`) }))
  if (href) acts.append(h('a', { class: 'btn btn-ghost btn-icon btn-sm', href, target: '_blank', rel: 'noopener noreferrer', 'aria-label': 'Open in a new tab', title: 'Open in a new tab' }, icon('external')))
  return h('div', { class: 'fld' }, h('div', { class: 'body' }, h('div', { class: 'k' }, label), v, extra), acts)
}

/** Live TOTP code with a countdown ring. Returns {el, stop}. */
export function totpRow(secret) {
  let spec
  try { spec = parseTotp(secret) } catch (e) { return { el: fieldRow({ label: 'One-time password', value: 'Invalid secret: ' + e.message, copyLabel: false }), stop() {} } }
  const code = h('span', { class: 'code', 'aria-live': 'off' }, '------')
  const holder = h('span')
  let current = ''
  let timer
  const tick = async () => {
    const now = Date.now()
    current = await totpCode(spec, now)
    const left = secondsRemaining(spec, now)
    code.textContent = current.replace(/(\d{3})(\d+)/, '$1 $2')
    holder.replaceChildren(ring(left / spec.period, left <= 5))
    holder.title = `${left} s left`
    timer = setTimeout(tick, 1000 - (now % 1000) + 5)
  }
  tick()
  const el = h('div', { class: 'fld' },
    h('div', { class: 'body' }, h('div', { class: 'k' }, 'One-time password'), h('div', { class: 'totp' }, code, holder)),
    h('div', { class: 'acts' }, iconButton({ label: 'Copy one-time password', icon: 'copy', onClick: () => copy(current, 'One-time password copied') })))
  return { el, stop: () => clearTimeout(timer) }
}

export const typeBadge = (type) => h('span', { class: 'badge' }, icon(TYPES[type].icon, 'icon-sm'), TYPES[type].label)

export function emptyState(ic, title, text, action) {
  return h('div', { class: 'empty' }, icon(ic, 'icon-lg'), h('h2', title), h('p', text), action)
}

export function spinner(text) { return h('div', { class: 'progress', role: 'status' }, h('span', { class: 'spin' }), text) }

export function pageHead(title, lead, ...actions) {
  return h('div', { class: 'page-head' }, h('h1', title), actions.length ? h('div', { class: 'cluster' }, actions) : null, lead ? h('p', { class: 'lead' }, lead) : null)
}

export function colorGenerated(pw) {
  const frag = document.createDocumentFragment()
  for (const ch of pw) {
    if (/[0-9]/.test(ch)) frag.append(h('span', { class: 'd' }, ch))
    else if (/[^A-Za-z0-9]/.test(ch)) frag.append(h('span', { class: 's' }, ch))
    else frag.append(ch)
  }
  return frag
}
