// Entry point: decides between setup, unlock and the application.
import { h, mount } from './dom.js'
import { onApiEvent } from './api.js'
import { vault, onBroadcast, loadSession, serverLocked, subscribe, wipe } from './vault.js'
import { setupView, unlockView } from './auth.js'
import { startShell } from './shell.js'
import { startIdle, stopIdle } from './idle.js'
import { applyTheme } from './prefs.js'
import { extensionInfo, canRunExtension } from './extension-promo.js'
import { href } from './router.js'

const root = document.getElementById('app')
let stopShell = null

let extensionAvailable = false

// Before the vault is open there is no settings page to go to, so the rail downloads the package directly; once it is open
// the same entry leads to the page that explains the installation.
function railLink() {
  if (!extensionAvailable || (vault.unlocked && !canRunExtension())) return null
  return vault.unlocked
    ? h('a', { href: href('/settings/extension') }, 'Browser extension')
    : h('a', { href: '/download/extension.zip', download: 'thevault-extension.zip' }, 'Download Chrome extension')
}

function render() {
  const links = vault.session?.apps || []
  const ext = railLink()
  mount(document.getElementById('family-nav'),
    links.length ? h('nav', { class: 'app-rail', 'aria-label': 'Your apps' }, ...links.map((app) => h('a', { href: app.launch_url }, app.name))) : null,
    ext ? h('nav', { class: 'app-rail', 'aria-label': 'Downloads' }, ext) : null)
  stopShell?.(); stopShell = null
  document.body.classList.remove('app-body', 'nav-open')
  root.className = 'app-root'
  document.body.classList.toggle('auth-body', !vault.unlocked)
  if (!vault.session) return
  const state = vault.session.vault.state
  if (state === 'none') { stopIdle(); setupView(root) }
  else if (!vault.unlocked) { stopIdle(); unlockView(root) }
  else { startIdle(); stopShell = startShell(root) }
}

function goSignIn(message) {
  wipe()
  location.assign('/login' + (message ? '?msg=' + encodeURIComponent(message) : ''))
}

onApiEvent('signedOut', (err) => goSignIn(err.code === 'session_revoked' ? 'Your access was removed in ClosedDoor.' : 'Your session ended. Sign in again.'))
onApiEvent('locked', () => { serverLocked() })
onBroadcast((kind) => { if (kind === 'lock') serverLocked(); else if (kind === 'signout') { wipe(); location.assign('/login') } })
subscribe((what) => { if (what === 'lock' || what === 'unlock') render() })

async function boot() {
  applyTheme()
  try {
    await loadSession()
    extensionAvailable = (await extensionInfo()).available === true
  } catch (e) {
    if (e.status === 401) return goSignIn()
    mount(root, h('p', { class: 'alert alert-error', role: 'alert' }, e.message || 'TheVault could not start.'))
    return
  }
  render()
}
boot()
