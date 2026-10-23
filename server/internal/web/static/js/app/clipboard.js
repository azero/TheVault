// Copy to the clipboard, and wipe it again after a delay if it still holds what we put there.
import { toast } from './dom.js'
import { prefs } from './prefs.js'

let timer
let lastText = null
let pending = null // text we copied and could not clear yet (the tab was not focused)

async function tryClear(text) {
  try {
    if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText('')
    return true
  } catch {
    try { await navigator.clipboard.writeText(''); return true } catch { return false } // both need a focused page
  }
}

// The usual case is: copy, switch to the other app, wait. The page is in the background then, so the clear fails; keep trying
// whenever the page is looked at again, and when it is locked, signed out of or closed.
const retry = async () => { if (pending !== null && document.visibilityState === 'visible' && (await tryClear(pending))) pending = null }
document.addEventListener('visibilitychange', retry)
window.addEventListener('focus', retry)
window.addEventListener('pagehide', () => { if (timer || pending !== null) navigator.clipboard?.writeText('').catch(() => {}) })

/** Called when the vault locks or the person signs out: clear now instead of waiting for the timer. */
export function forgetClipboard() {
  if (timer) { clearTimeout(timer); timer = null; pending = lastText }
  if (pending !== null) tryClear(pending).then((ok) => { if (ok) pending = null })
}

export async function copy(text, label = 'Copied') {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    toast('The browser blocked copying. Click the page and try again.', 'error')
    return
  }
  const secs = prefs.get('clipboardSeconds')
  toast(secs ? `${label}. The clipboard clears in about ${secs} s.` : label)
  clearTimeout(timer)
  timer = null
  pending = null
  lastText = text
  if (secs > 0) {
    timer = setTimeout(async () => {
      timer = null
      if (!(await tryClear(text))) pending = text
    }, secs * 1000)
  }
}
