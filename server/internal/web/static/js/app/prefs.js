// Per-browser, non-secret preferences (theme, clipboard clearing, remembered tabs). Never holds anything from the vault.
const DEFAULTS = { clipboardSeconds: 30, theme: 'auto', sort: 'name' }
const KEY = 'vault-prefs'

function read() {
  try { return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) || '{}') } } catch { return { ...DEFAULTS } }
}

export const prefs = {
  get(k) { return read()[k] },
  set(k, v) {
    const p = read(); p[k] = v
    try { localStorage.setItem(KEY, JSON.stringify(p)) } catch { /* storage blocked */ }
  },
}

export function applyTheme(t = prefs.get('theme')) {
  const root = document.documentElement
  if (t === 'light' || t === 'dark') root.dataset.theme = t
  else delete root.dataset.theme
  try { if (t === 'light' || t === 'dark') localStorage.setItem('vault-theme', t); else localStorage.removeItem('vault-theme') } catch { /* ignore */ }
}
