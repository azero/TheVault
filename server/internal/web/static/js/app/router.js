// Hash routing. The fragment never reaches the server, so item and space ids stay out of access logs.
const listeners = new Set()

export function parse(hash = location.hash) {
  const raw = hash.replace(/^#/, '') || '/all'
  const [pathPart, qs = ''] = raw.split('?')
  const query = Object.fromEntries(new URLSearchParams(qs))
  let path = pathPart.startsWith('/') ? pathPart : '/' + pathPart
  let itemId = null
  const m = /^(.*)\/item\/([0-9a-f]{32})$/.exec(path)
  if (m) { path = m[1] || '/all'; itemId = m[2] }
  const seg = path.split('/').filter(Boolean).map(decodeURIComponent)
  return { path, seg, query, itemId, raw }
}

export function href(path, query) {
  const q = query && Object.keys(query).length ? '?' + new URLSearchParams(query) : ''
  return '#' + path + q
}

export const navigate = (path, query, { replace = false } = {}) => {
  const target = href(path, query)
  if (replace) history.replaceState(null, '', target)
  if (location.hash === target) listeners.forEach((f) => f(parse()))
  else if (replace) listeners.forEach((f) => f(parse()))
  else location.hash = target
}

export const onRoute = (fn) => { listeners.add(fn); return () => listeners.delete(fn) }
window.addEventListener('hashchange', () => listeners.forEach((f) => f(parse())))
