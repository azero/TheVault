// Copy to the clipboard, and wipe it again after a delay if it still holds what we put there.
import { toast } from './dom.js'
import { prefs } from './prefs.js'

let timer
export async function copy(text, label = 'Copied') {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    toast('The browser blocked copying. Click the page and try again.', 'error')
    return
  }
  const secs = prefs.get('clipboardSeconds')
  toast(secs ? `${label}. The clipboard clears in ${secs} s.` : label)
  clearTimeout(timer)
  if (secs > 0) {
    timer = setTimeout(async () => {
      try {
        if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText('')
      } catch { try { await navigator.clipboard.writeText('') } catch { /* needs focus: best effort */ } }
    }, secs * 1000)
  }
}
