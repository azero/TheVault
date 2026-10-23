// Tiny DOM helpers for the extension pages (the same rules as the web app: never build HTML from strings).
const SVG_NS = 'http://www.w3.org/2000/svg'
const SAFE_HREF = /^(https?:|#)/i

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag)
  if (attrs && (typeof attrs !== 'object' || attrs instanceof Node || Array.isArray(attrs))) { kids.unshift(attrs); attrs = null }
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === false || v == null) continue
    if (k === 'class') el.className = v
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn)
    else if (['value', 'checked', 'disabled', 'selected'].includes(k)) el[k] = v
    else if (k === 'href' && !SAFE_HREF.test(v)) continue
    else if (k.startsWith('on') || k === 'style') throw new Error('not allowed: ' + k)
    else el.setAttribute(k, v === true ? '' : String(v))
  }
  const add = (list) => { for (const c of list) { if (c == null || c === false) continue; if (Array.isArray(c)) add(c); else el.append(c instanceof Node ? c : document.createTextNode(String(c))) } }
  add(kids)
  return el
}

export function icon(name, cls = '') {
  const svg = document.createElementNS(SVG_NS, 'svg')
  svg.setAttribute('class', 'icon ' + cls); svg.setAttribute('aria-hidden', 'true')
  const use = document.createElementNS(SVG_NS, 'use')
  use.setAttribute('href', 'icons.svg#i-' + name)
  svg.append(use)
  return svg
}

export function mount(el, ...kids) { el.replaceChildren(...kids.flat().filter((k) => k != null && k !== false)) }

let box
export function toast(msg, type = 'ok', ms = 2600) {
  if (!box) { box = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' }); document.body.append(box) }
  const t = h('div', { class: 'toast ' + (type === 'error' ? 'error' : '') }, icon(type === 'error' ? 'alert' : 'check'), h('span', msg))
  box.append(t)
  setTimeout(() => t.remove(), ms)
}

export function avatarClass(seed) { let n = 0; for (const ch of String(seed)) n = (n * 31 + ch.charCodeAt(0)) >>> 0; return 'av-' + (n % 8) }
export function initials(name) { const p = String(name || '?').trim().split(/[\s@._-]+/).filter(Boolean); return ((p[0]?.[0] ?? '?') + (p.length > 1 ? p.at(-1)[0] : '')).toUpperCase() }
export function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms) } }
