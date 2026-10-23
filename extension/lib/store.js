// Thin wrappers over chrome.storage. What lives where (see docs/extension.md):
//   local   server origin, bearer token, the ENCRYPTED vault cache, preferences. Never decrypted data, never a key.
//   session the unlock key and short-lived "save this login?" prompts. In memory only, cleared when the browser closes,
//           and not readable by content scripts (the default access level).
export const local = {
  get: async (k) => (await chrome.storage.local.get(k))[k],
  set: (o) => chrome.storage.local.set(o),
  remove: (k) => chrome.storage.local.remove(k),
}
export const session = {
  get: async (k) => (await chrome.storage.session.get(k))[k],
  set: (o) => chrome.storage.session.set(o),
  remove: (k) => chrome.storage.session.remove(k),
}

export const DEFAULT_PREFS = { clipboardSeconds: 30, offlineCache: true, idleMinutes: 15 }
export async function getPrefs() { return { ...DEFAULT_PREFS, ...((await local.get('prefs')) ?? {}) } }
export async function setPrefs(p) { await local.set({ prefs: { ...(await getPrefs()), ...p } }) }

/** https only, except loopback for development. Returns the origin or throws. */
export function normalizeServer(input) {
  let u
  try { u = new URL(String(input).trim()) } catch { throw new Error('Enter the full address, for example https://vault.example.com') }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) throw new Error('The address must start with https://')
  if (u.username || u.password) throw new Error('Do not put a user name or password in the address.')
  return u.origin
}
