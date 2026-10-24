// Talking to the vault server: bearer-token API calls and the sign-in flow through ClosedDoor (see docs/extension.md).
// The extension never talks to ClosedDoor itself: the vault server runs the SSO flow and hands back a one-time code.
import { b64uEncode, utf8 } from '../core/b64.js'
import { randomBytes, sha256 } from '../core/crypto.js'
import { local, session, normalizeServer } from './store.js'

export class ExtError extends Error {
  constructor(code, message, extra = {}) { super(message); this.code = code; Object.assign(this, extra) }
}

export async function getConfig() {
  const [server, token, user] = await Promise.all([local.get('server'), local.get('token'), local.get('user')])
  return { server, token, user }
}

export async function api(method, path, body, { token: tokenOverride, noAuth = false } = {}) {
  const { server, token } = await getConfig()
  if (!server) throw new ExtError('not_configured', 'Set the vault address first.')
  const headers = { Accept: 'application/json' }
  const t = tokenOverride ?? token
  if (!noAuth) {
    if (!t) throw new ExtError('signed_out', 'Sign in first.')
    headers.Authorization = 'Bearer ' + t
  }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  let res
  try {
    res = await fetch(server + '/api/v1' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store', credentials: 'omit' })
  } catch {
    throw new ExtError('network', 'Cannot reach the vault server.')
  }
  let data = null
  try { data = await res.json() } catch { /* no body */ }
  if (res.ok) return data
  const code = data?.error || 'error'
  if (res.status === 401 && (code === 'unauthenticated' || code === 'session_revoked')) {
    await local.remove('token')
    await session.remove('uk')
    throw new ExtError('signed_out', code === 'session_revoked' ? 'Your access was removed in ClosedDoor.' : 'Sign in again.')
  }
  if (res.status === 423) { await session.remove('uk'); throw new ExtError('locked', 'The vault is locked.') }
  throw new ExtError(code, data?.message || 'The request failed.', { status: res.status, body: data, retryAfter: Number(res.headers.get('Retry-After') || data?.retry_after || 0) })
}

async function platformLabel() {
  try { const p = await chrome.runtime.getPlatformInfo(); return 'Chrome extension on ' + ({ win: 'Windows', mac: 'macOS', linux: 'Linux', cros: 'ChromeOS', android: 'Android' }[p.os] ?? p.os) } catch { return 'Chrome extension' }
}

/**
 * Sign in through the server (which runs ClosedDoor). `silent` uses prompt=none so a live ClosedDoor session signs in without
 * any window; if there is none the flow fails and the caller may retry interactively. A renewal presents the old token, so an
 * unlocked vault stays unlocked.
 */
export async function signIn({ silent = false } = {}) {
  const { server, token } = await getConfig()
  if (!server) throw new ExtError('not_configured', 'Set the vault address first.')
  const verifier = b64uEncode(randomBytes(48))
  const challenge = b64uEncode(await sha256(utf8(verifier)))
  const state = b64uEncode(randomBytes(16))
  const redirect = chrome.identity.getRedirectURL('cb')
  const q = new URLSearchParams({ redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256', state })
  if (silent) q.set('prompt', 'none')
  let final
  try {
    final = await chrome.identity.launchWebAuthFlow({ url: `${server}/ext/auth?${q}`, interactive: !silent })
  } catch (e) {
    throw new ExtError(silent ? 'interaction_required' : 'cancelled', silent ? 'Sign in again.' : 'Sign-in was cancelled.', { cause: e?.message })
  }
  const back = new URL(final)
  if (back.searchParams.get('state') !== state) throw new ExtError('bad_state', 'The sign-in response did not match the request.')
  const err = back.searchParams.get('error')
  if (err) throw new ExtError(err === 'login_required' ? 'interaction_required' : err, err === 'access_denied' ? 'This account may not use TheVault.' : err === 'login_required' ? 'Sign in again.' : 'Sign-in failed (' + err + ').')
  const code = back.searchParams.get('code')
  if (!code) throw new ExtError('bad_response', 'The sign-in response had no code.')
  const res = await api('POST', '/ext/token', { code, verifier, redirect_uri: redirect, label: await platformLabel() }, { token, noAuth: !token })
  await adoptAccount(res.user.sub)
  await local.set({ token: res.token, user: res.user })
  return res.user
}

/**
 * The offline cache and the unlock key belong to one person. When a different account signs in here (a shared browser
 * profile, or ClosedDoor switched users behind a silent renewal) neither may be carried over: the new person must not
 * inherit the previous person's encrypted vault, nor a vault that is still unlocked for them, and their own incremental
 * sync must not start from the previous person's position. A cache with no recorded owner (written before this check
 * existed) is trusted only while the previous account is still the one signed in.
 */
export async function adoptAccount(sub) {
  const owner = (await local.get('cacheOwner')) ?? (await local.get('user'))?.sub
  if (owner !== sub) {
    await local.remove('cache')
    await session.remove(['uk', 'unlockedAt', 'offline', 'prompts'])
  }
  await local.set({ cacheOwner: sub })
}

export { normalizeServer }
