// Thin fetch wrapper: CSRF header, JSON, uniform errors, and the three session-level reactions (sign in again,
// vault locked by the server, rate limited).
export class ApiError extends Error {
  constructor(status, body) {
    super(body?.message || 'The request failed.')
    this.status = status; this.code = body?.error || 'error'; this.body = body || {}
  }
}

const listeners = { locked: [], signedOut: [] }
export const onApiEvent = (name, fn) => listeners[name].push(fn)
const emit = (name, arg) => listeners[name].forEach((f) => f(arg))

let csrf = ''
export const setCsrf = (t) => { csrf = t }

export async function api(method, path, body) {
  const init = { method, headers: { Accept: 'application/json' }, credentials: 'same-origin', cache: 'no-store' }
  if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body) }
  if (method !== 'GET') init.headers['X-Vault-CSRF'] = csrf
  let res
  try { res = await fetch('/api/v1' + path, init) } catch { throw new ApiError(0, { error: 'network', message: 'Cannot reach the server. Check your connection.' }) }
  let data = null
  try { data = await res.json() } catch { /* empty body */ }
  if (res.ok) return data
  const err = new ApiError(res.status, data)
  if (res.status === 401 && (err.code === 'unauthenticated' || err.code === 'session_revoked')) emit('signedOut', err)
  else if (res.status === 423) emit('locked', err)
  else if (res.status === 429) err.retryAfter = Number(res.headers.get('Retry-After') || data?.retry_after || 0)
  throw err
}

export const get = (p) => api('GET', p)
export const post = (p, b = {}) => api('POST', p, b)
export const put = (p, b) => api('PUT', p, b)
export const del = (p) => api('DELETE', p)
