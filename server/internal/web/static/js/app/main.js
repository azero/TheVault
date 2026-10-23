// Entry point: decides between setup, unlock and the application.
import { h, mount } from './dom.js'
import { onApiEvent } from './api.js'
import { vault, onBroadcast, loadSession, serverLocked, subscribe, wipe } from './vault.js'
import { setupView, unlockView } from './auth.js'
import { startShell } from './shell.js'
import { startIdle, stopIdle } from './idle.js'
import { applyTheme } from './prefs.js'

const root = document.getElementById('app')
let stopShell = null

function render() {
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
  } catch (e) {
    if (e.status === 401) return goSignIn()
    mount(root, h('p', { class: 'alert alert-error', role: 'alert' }, e.message || 'TheVault could not start.'))
    return
  }
  render()
}
boot()
