// The only way the UI creates DOM. It never parses HTML: strings become text nodes, attributes are set one by one, and
// links are restricted to http(s)/mailto/same-site. With Trusted Types enforced by the CSP, innerHTML would throw anyway.
const SVG_NS = 'http://www.w3.org/2000/svg'
const SAFE_HREF = /^(https?:|mailto:|\/(?!\/)|#)/i

function setAttr(el, k, v) {
  if (v === false || v == null) return
  if (k === 'class') el.className = v
  else if (k === 'text') el.textContent = v
  else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn)
  else if (k === 'dataset') Object.assign(el.dataset, v)
  else if (k === 'value' || k === 'checked' || k === 'selected' || k === 'disabled' || k === 'indeterminate') el[k] = v
  else if (k === 'href' || k === 'src') {
    if (k === 'href' && !SAFE_HREF.test(String(v))) return
    if (k === 'src' && !/^(\/static\/|data:image\/)/.test(String(v))) return
    el.setAttribute(k, v)
  } else if (k.startsWith('on')) throw new Error('inline event handlers are not allowed: use { on: { click } }')
  else if (k === 'style') throw new Error('inline styles are not allowed: add a class to app.css')
  else el.setAttribute(k, v === true ? '' : String(v))
}

function append(el, kids) {
  for (const c of kids) {
    if (c == null || c === false) continue
    if (Array.isArray(c)) append(el, c)
    else if (c instanceof Node) el.append(c)
    else el.append(document.createTextNode(String(c)))
  }
}

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag)
  if (attrs && (typeof attrs !== 'object' || attrs instanceof Node || Array.isArray(attrs))) { kids.unshift(attrs); attrs = null }
  if (attrs) for (const [k, v] of Object.entries(attrs)) setAttr(el, k, v)
  append(el, kids)
  return el
}

export function icon(name, cls = '') {
  const svg = document.createElementNS(SVG_NS, 'svg')
  svg.setAttribute('class', 'icon ' + cls)
  svg.setAttribute('aria-hidden', 'true')
  const use = document.createElementNS(SVG_NS, 'use')
  use.setAttribute('href', '/static/icons.svg#i-' + name)
  svg.append(use)
  return svg
}

export function ring(fraction, low) {
  const r = 14, c = 2 * Math.PI * r
  const svg = document.createElementNS(SVG_NS, 'svg')
  svg.setAttribute('class', 'ring' + (low ? ' low' : ''))
  svg.setAttribute('viewBox', '0 0 34 34')
  svg.setAttribute('aria-hidden', 'true')
  for (const cls of ['bg', 'fg']) {
    const ci = document.createElementNS(SVG_NS, 'circle')
    ci.setAttribute('class', cls); ci.setAttribute('cx', '17'); ci.setAttribute('cy', '17'); ci.setAttribute('r', String(r))
    if (cls === 'fg') { ci.setAttribute('stroke-dasharray', String(c)); ci.setAttribute('stroke-dashoffset', String(c * (1 - fraction))) }
    svg.append(ci)
  }
  return svg
}

export function clear(el) { while (el.firstChild) el.firstChild.remove() }
export function mount(el, ...kids) { clear(el); append(el, kids) }

let toastBox
export function toast(msg, type = 'ok', ms = 3500) {
  if (!toastBox) {
    toastBox = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' })
    document.body.append(toastBox)
  }
  const t = h('div', { class: 'toast ' + (type === 'error' ? 'error' : '') }, icon(type === 'error' ? 'alert' : 'check'), h('span', msg))
  toastBox.append(t)
  while (toastBox.children.length > 3) toastBox.firstChild.remove()
  setTimeout(() => t.remove(), type === 'error' ? ms + 2500 : ms)
}

const palette = 8
export function avatarClass(seed) {
  let n = 0
  for (const ch of String(seed)) n = (n * 31 + ch.charCodeAt(0)) >>> 0
  return 'av-' + (n % palette)
}
export function initials(name) {
  const parts = String(name || '?').trim().split(/[\s@._-]+/).filter(Boolean)
  return ((parts[0]?.[0] ?? '?') + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase()
}

export function timeAgo(sec, now = Date.now() / 1000) {
  if (!sec) return 'never'
  const d = Math.max(0, now - sec)
  if (d < 45) return 'just now'
  if (d < 3600) return Math.round(d / 60) + ' min ago'
  if (d < 86400) return Math.round(d / 3600) + ' h ago'
  if (d < 86400 * 30) return Math.round(d / 86400) + ' d ago'
  return new Date(sec * 1000).toLocaleDateString()
}
export const fmtDateTime = (sec) => (sec ? new Date(sec * 1000).toLocaleString() : 'never')
export const fmtBytes = (n) => (n > 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : n > 1024 ? (n / 1024).toFixed(0) + ' KB' : n + ' B')

export function debounce(fn, ms) {
  let t
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms) }
}

/** Move focus into a freshly rendered view without scrolling surprises. */
export function focusFirst(root, sel = 'input:not([type=hidden]), button.btn-primary, [autofocus]') {
  root.querySelector(sel)?.focus({ preventScroll: true })
}
