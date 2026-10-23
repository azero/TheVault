// Client-side auto-lock. The server enforces its own idle window; this makes the browser let go of the keys at the same
// time, and keeps the server window alive while the person is actually using the page.
import { vault, lock, ping } from './vault.js'

let timer, last = Date.now(), pinged = 0

const touch = () => { last = Date.now() }
const events = ['pointerdown', 'keydown', 'wheel', 'touchstart']

export function startIdle() {
  stopIdle()
  last = Date.now(); pinged = Date.now()
  events.forEach((e) => window.addEventListener(e, touch, { passive: true }))
  timer = setInterval(() => {
    if (!vault.unlocked) return
    const idleMs = (vault.session?.idle_lock_minutes ?? 15) * 60 * 1000
    const now = Date.now()
    if (now - last >= idleMs) { lock(); return }
    // keep the server-side window open while the page is in use (it slides on every API call, but reading is silent)
    if (now - last < idleMs && now - pinged > Math.min(idleMs / 3, 4 * 60 * 1000)) { pinged = now; ping() }
  }, 10000)
}

export function stopIdle() {
  clearInterval(timer)
  events.forEach((e) => window.removeEventListener(e, touch))
}
