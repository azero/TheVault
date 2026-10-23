// First-run setup, unlock, and recovery. These are the only screens where the master password is typed.
import { h, icon, avatarClass, initials, mount, focusFirst, toast } from './dom.js'
import { post, ApiError } from './api.js'
import { vault, broadcast, unlock, setupVaultFlow, finishSetup, recoverWithKey, afterRecovery, UserError } from './vault.js'
import { strengthMeter, spinner } from './components.js'
import { alertBox } from './dialog.js'
import { estimateStrength } from '../core/strength.js'

export const MIN_PASSWORD = 12

const logo = () => h('h1', { class: 'logo-h' }, h('img', { class: 'logo', src: '/static/brand/thevault-logo.webp', width: 760, height: 253, alt: 'TheVault' }))

function shell(card, ...extra) {
  return h('main', { id: 'main', class: 'auth-wrap' }, card, ...extra)
}

function whoBox() {
  const u = vault.me
  return h('div', { class: 'who' },
    h('span', { class: `avatar ${avatarClass(u.sub)}` }, initials(u.name || u.email)),
    h('div', {}, h('div', { class: 'name' }, u.name || u.email), h('div', { class: 'muted small' }, u.email)))
}

async function signOut() {
  broadcast('signout')
  try {
    const r = await post('/session/logout')
    location.assign(r.redirect || '/login')
  } catch { location.assign('/login') }
}

function passwordProblem(pw, email) {
  if (pw.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters. A few random words work well.`
  if (email && pw.toLowerCase().includes(email.split('@')[0].toLowerCase()) && email.split('@')[0].length > 3) return 'Do not use your name or email in the password.'
  if (estimateStrength(pw).score < 2) return 'That password is too easy to guess. Add more words or characters.'
  return ''
}

// ---------- unlock ----------

export function unlockView(root) {
  const pw = h('input', { class: 'input', id: 'master', type: 'password', autocomplete: 'current-password', required: true, 'aria-describedby': 'unlock-msg' })
  const msg = h('div', { id: 'unlock-msg', 'aria-live': 'polite' })
  const btn = h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, icon('unlock'), 'Unlock')
  let countdown
  const show = (kind, text) => mount(msg, text ? alertBox(kind, text) : null)
  const lockout = (secs) => {
    clearInterval(countdown)
    let left = secs
    btn.disabled = true
    const draw = () => show('error', `Too many wrong passwords. Try again in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}.`)
    draw()
    countdown = setInterval(() => { left -= 1; if (left <= 0) { clearInterval(countdown); btn.disabled = false; show('', '') } else draw() }, 1000)
  }
  const form = h('form', { class: 'stack', novalidate: true, on: { submit: async (e) => {
    e.preventDefault()
    if (!pw.value) return
    btn.disabled = true
    btn.replaceChildren(h('span', { class: 'spin' }), 'Unlocking…')
    show('', '')
    try {
      await unlock(pw.value)
      pw.value = ''
    } catch (err) {
      btn.replaceChildren(icon('unlock'), 'Unlock')
      btn.disabled = false
      if (err instanceof ApiError && err.code === 'sso_expired') { silentSignIn(); return }
      if (err instanceof ApiError && (err.code === 'locked_out' || err.retryAfter || err.body.retry_after)) lockout(err.retryAfter || err.body.retry_after || 60)
      else if (err instanceof ApiError && err.code === 'bad_password') show('error', 'That master password is not correct.' + (err.body.failed >= 3 ? ' Repeated mistakes lock the vault for a few minutes.' : ''))
      else show('error', err.message || 'Could not unlock.')
      pw.select()
    }
  } } },
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'master' }, 'Master password'), pw), msg, btn)

  const card = h('section', { class: 'auth-card' }, logo(), whoBox(), form,
    h('div', { class: 'cluster', 'aria-label': 'Other options' },
      h('button', { class: 'btn btn-ghost btn-sm', type: 'button', on: { click: () => recoveryView(root) } }, icon('key'), 'Use recovery key'),
      h('span', { class: 'spacer' }),
      h('button', { class: 'btn btn-ghost btn-sm', type: 'button', on: { click: signOut } }, icon('logout'), 'Sign out')))
  mount(root, shell(card, h('p', { class: 'foot muted' }, 'Your master password never leaves this device.')))
  focusFirst(root)
  if (!vault.session.sso.fresh) silentSignIn(true)
}

/** The ClosedDoor token has expired: bounce through SSO silently (the vault is locked, so no state is lost). */
export function silentSignIn(auto = false) {
  const key = 'vault-silent-' + vault.me.sub
  const last = Number(sessionStorage.getItem(key) || 0)
  if (auto && Date.now() - last < 20000) return // do not loop if ClosedDoor keeps answering "login required"
  sessionStorage.setItem(key, String(Date.now()))
  location.assign('/auth/login?silent=1&return=/')
}

// ---------- setup ----------

export function setupView(root) {
  const email = vault.me.email
  const pw = h('input', { class: 'input', id: 'new-pw', type: 'password', autocomplete: 'new-password', required: true, minlength: MIN_PASSWORD, 'aria-describedby': 'pw-hint' })
  const pw2 = h('input', { class: 'input', id: 'new-pw2', type: 'password', autocomplete: 'new-password', required: true })
  const meter = strengthMeter(() => pw.value)
  pw.addEventListener('input', () => meter.update())
  const err = h('div', { 'aria-live': 'polite' })
  const submit = h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, 'Create my vault')
  const form = h('form', { class: 'stack', novalidate: true, on: { submit: async (e) => {
    e.preventDefault()
    const problem = passwordProblem(pw.value, email) || (pw.value !== pw2.value ? 'The two passwords do not match.' : '')
    if (problem) { mount(err, alertBox('error', problem)); return }
    mount(err, null)
    submit.disabled = true
    mount(root, shell(h('section', { class: 'auth-card' }, logo(), spinner('Deriving your keys on this device… this takes a moment on purpose.'))))
    try {
      const created = await setupVaultFlow(pw.value)
      recoveryStep(root, created, pw.value)
    } catch (e2) {
      setupView(root)
      mount(err, alertBox('error', e2.message))
    }
  } } },
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'new-pw' }, 'Master password'), pw, meter.el,
    h('span', { class: 'hint', id: 'pw-hint' }, `At least ${MIN_PASSWORD} characters. Four or five unrelated words is easy to remember and hard to guess.`)),
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'new-pw2' }, 'Repeat master password'), pw2),
  err, submit)
  const card = h('section', { class: 'auth-card' }, logo(),
    h('div', { class: 'steps', 'aria-hidden': 'true' }, h('span', { class: 'on' }), h('span'), h('span')),
    h('h2', {}, `Welcome, ${(vault.me.name || vault.me.email).split(' ')[0]}`),
    h('p', { class: 'muted' }, 'Choose a master password. It encrypts your vault on this device, so we cannot read your data and cannot reset this password for you. You will get a recovery key in the next step.'),
    form)
  mount(root, shell(card, h('p', { class: 'foot muted' }, `Signed in as ${vault.me.email} · `, h('a', { href: '#', on: { click: (e) => { e.preventDefault(); signOut() } } }, 'Sign out'))))
  focusFirst(root)
}

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  const a = h('a', { href: '#' }); a.href = url; a.download = name
  document.body.append(a); a.click(); a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 5000)
}

export function recoveryKitText(key, email) {
  return `TheVault recovery kit\n\nAccount: ${email}\nCreated: ${new Date().toISOString().slice(0, 10)}\n\nRecovery key:\n${key}\n\n` +
    'Keep this somewhere safe and offline (a printout in a safe works well). Anyone with this key AND access to your\nClosedDoor sign-in can open your vault. If you forget your master password, this key is the only way back in.\n'
}

function recoveryStep(root, created, password, { onDone, title } = {}) {
  const key = created.recoveryKey
  const last = key.split('-').pop()
  const confirmInput = h('input', { class: 'input mono', id: 'confirm-last', autocomplete: 'off', spellcheck: 'false', maxlength: 6, 'aria-describedby': 'confirm-hint' })
  const saved = h('input', { type: 'checkbox', id: 'saved' })
  const err = h('div', { 'aria-live': 'polite' })
  const go = h('button', { class: 'btn btn-primary btn-block', type: 'submit', disabled: true }, 'Finish')
  const check = () => { go.disabled = !(saved.checked && confirmInput.value.trim().toUpperCase() === last) }
  saved.addEventListener('change', check); confirmInput.addEventListener('input', check)
  const form = h('form', { class: 'stack', novalidate: true, on: { submit: async (e) => {
    e.preventDefault()
    go.disabled = true
    try { await (onDone ? onDone() : finishSetup(created, password)) } catch (e2) { mount(err, alertBox('error', e2.message)); go.disabled = false }
  } } },
  h('div', { class: 'recovery', 'aria-label': 'Your recovery key' }, key.split('-').join(' ')),
  h('div', { class: 'cluster no-print' },
    h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => download('thevault-recovery-key.txt', recoveryKitText(key, vault.me.email)) } }, icon('download'), 'Download'),
    h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => window.print() } }, icon('print'), 'Print')),
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'confirm-last' }, 'Type the last group of the key to confirm you have it'), confirmInput,
    h('span', { class: 'hint', id: 'confirm-hint' }, 'The final group of six characters, from the key above.')),
  h('label', { class: 'check' }, saved, h('span', {}, 'I stored the recovery key somewhere safe.')),
  err, go)
  const card = h('section', { class: 'auth-card wide' }, logo(),
    h('div', { class: 'steps', 'aria-hidden': 'true' }, h('span', { class: 'on' }), h('span', { class: 'on' }), h('span')),
    h('h2', {}, title || 'Save your recovery key'),
    alertBox('warn', h('span', {}, h('strong', {}, 'This is shown once. '), 'If you forget your master password, only this key can recover your vault. We cannot.')),
    form)
  mount(root, shell(card))
  focusFirst(root, '#confirm-last')
}

// ---------- recovery ----------

export function recoveryView(root) {
  const keyIn = h('input', { class: 'input mono', id: 'rkey', autocomplete: 'off', spellcheck: 'false', required: true, placeholder: 'XXXXXX-XXXXXX-…' })
  const pw = h('input', { class: 'input', id: 'rpw', type: 'password', autocomplete: 'new-password', required: true, minlength: MIN_PASSWORD })
  const pw2 = h('input', { class: 'input', id: 'rpw2', type: 'password', autocomplete: 'new-password', required: true })
  const meter = strengthMeter(() => pw.value)
  pw.addEventListener('input', () => meter.update())
  const err = h('div', { 'aria-live': 'polite' })
  const btn = h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, 'Recover my vault')
  const form = h('form', { class: 'stack', novalidate: true, on: { submit: async (e) => {
    e.preventDefault()
    const problem = passwordProblem(pw.value, vault.me.email) || (pw.value !== pw2.value ? 'The two passwords do not match.' : '')
    if (problem) { mount(err, alertBox('error', problem)); return }
    btn.disabled = true; mount(err, null)
    btn.replaceChildren(h('span', { class: 'spin' }), 'Recovering…')
    try {
      const newKey = await recoverWithKey(keyIn.value, pw.value)
      recoveryStep(root, { recoveryKey: newKey }, pw.value, { title: 'Save your new recovery key', onDone: afterRecovery })
    } catch (e2) {
      btn.disabled = false; btn.replaceChildren('Recover my vault')
      const m = e2 instanceof ApiError && e2.code === 'sso_expired' ? 'Your sign-in expired. Sign in again.' : e2.message?.includes('decryption failed') ? 'That recovery key does not open this vault.' : e2.message
      mount(err, alertBox('error', m))
      if (e2 instanceof ApiError && e2.code === 'sso_expired') silentSignIn()
    }
  } } },
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'rkey' }, 'Recovery key'), keyIn),
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'rpw' }, 'New master password'), pw, meter.el),
  h('div', { class: 'field' }, h('label', { class: 'label', for: 'rpw2' }, 'Repeat new master password'), pw2),
  err, btn)
  const card = h('section', { class: 'auth-card' }, logo(), h('h2', {}, 'Recover with your recovery key'),
    h('p', { class: 'muted' }, 'Enter the recovery key you saved when you created your vault, then choose a new master password. Your data stays intact. Your other sessions and devices will be signed out.'),
    form,
    h('p', {}, h('button', { class: 'btn btn-ghost btn-sm', type: 'button', on: { click: () => unlockView(root) } }, icon('arrow-left'), 'Back to unlock')))
  mount(root, shell(card))
  focusFirst(root)
}

export { UserError, toast }
