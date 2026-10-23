// Content script (runs in every frame of https pages and localhost). It is deliberately small and passive:
//  - it NEVER fills anything on its own; it fills only when the service worker sends a `fill` message, and the service
//    worker only does that after checking this frame's address against the saved website rules;
//  - it never holds a secret except for the instant of a submit (to offer "save this login?") and the moment of a fill;
//  - it only touches fields that are visible to the person (no hidden or off-screen inputs).
(() => {
  if (window.__thevaultContent) return
  window.__thevaultContent = true

  const send = (m) => new Promise((res) => { try { chrome.runtime.sendMessage(m, (r) => res(chrome.runtime.lastError ? null : r)) } catch { res(null) } })

  // ---------- finding fields ----------

  function usable(el) {
    if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly || !el.isConnected) return false
    const r = el.getBoundingClientRect()
    if (r.width < 8 || r.height < 8) return false
    const x = r.left + window.scrollX, y = r.top + window.scrollY
    if (x + r.width < 0 || y + r.height < 0) return false // pushed off the page to hide it
    if (typeof el.checkVisibility === 'function' && !el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false
    const cs = getComputedStyle(el)
    return cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity) > 0.1
  }

  const TEXTY = new Set(['text', 'email', 'tel', ''])
  const NOT_USERNAME = /search|captcha|otp|totp|code|query|zip|postal|phone|coupon|promo/i

  function passwordFields(root = document) {
    return [...root.querySelectorAll('input[type="password"]')].filter(usable)
  }

  function usernameFor(pw) {
    const scope = pw.form ?? document
    const inputs = [...scope.querySelectorAll('input')].filter((i) => TEXTY.has((i.getAttribute('type') || '').toLowerCase()) && usable(i))
    const before = inputs.filter((i) => i.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING)
    const ranked = before.filter((i) => !NOT_USERNAME.test(`${i.name} ${i.id} ${i.placeholder}`) || /user|login|email/i.test(i.autocomplete))
    return ranked.at(-1) ?? null
  }

  function usernameOnlyField() {
    return [...document.querySelectorAll('input')].filter((i) => usable(i) && (/^(username|email)$/i.test(i.autocomplete) || (i.type || '').toLowerCase() === 'email')).at(0) ?? null
  }

  function otpFields() {
    return [...document.querySelectorAll('input')].filter((i) => usable(i) && (/one-time-code/i.test(i.autocomplete) || /^(otp|totp|mfa|verification|authenticator)/i.test(`${i.name}${i.id}`)))
  }

  function setValue(el, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set // frameworks watch the native setter
    setter.call(el, value)
    el.dispatchEvent(new Event('input', { bubbles: true }))
    el.dispatchEvent(new Event('change', { bubbles: true }))
  }

  // ---------- filling (only on the service worker's say-so) ----------

  chrome.runtime.onMessage.addListener((m, sender, respond) => {
    if (sender.id !== chrome.runtime.id) return false
    if (m?.type === 'fill') {
      let filled = 0
      const pws = passwordFields()
      if (pws.length) {
        const pw = pws[0]
        const user = usernameFor(pw)
        if (user && m.username) { setValue(user, m.username); filled++ }
        if (m.password) { setValue(pw, m.password); filled++ }
      } else {
        const user = usernameOnlyField()
        if (user && m.username) { setValue(user, m.username); filled++ }
      }
      if (m.otp) for (const f of otpFields()) if (!f.value) { setValue(f, m.otp); filled++; break }
      respond({ filled })
      return false
    }
    if (m?.type === 'showSave' && window === window.top) { showSaveBar(); respond({}); return false }
    return false
  })

  // ---------- noticing a login so it can be saved ----------

  let lastSent = ''
  function captureFrom(form) {
    const scope = form ?? document
    const pws = [...scope.querySelectorAll('input[type="password"]')].filter((p) => p.value)
    if (!pws.length) return
    const fresh = pws.filter((p) => /new-password/i.test(p.autocomplete))
    const pw = fresh[0] ?? pws[0]
    const user = usernameFor(pw)
    const payload = { type: 'captured', username: user?.value ?? '', password: pw.value }
    const key = payload.username + '\0' + payload.password
    if (key === lastSent) return
    lastSent = key
    setTimeout(() => { lastSent = '' }, 4000)
    send(payload)
  }

  document.addEventListener('submit', (e) => { if (e.isTrusted && e.target instanceof HTMLFormElement) captureFrom(e.target) }, true)
  document.addEventListener('click', (e) => {
    if (!e.isTrusted) return
    const b = e.target instanceof Element ? e.target.closest('button, input[type="submit"], [role="button"]') : null
    if (b && (b.form || b.closest('form'))) captureFrom(b.form ?? b.closest('form'))
    else if (b && passwordFields().length) captureFrom(null)
  }, true)
  document.addEventListener('keydown', (e) => {
    if (e.isTrusted && e.key === 'Enter' && e.target instanceof HTMLInputElement) captureFrom(e.target.form)
  }, true)

  // ---------- the "save this login?" bar (top frame only) ----------

  let bar = null
  async function showSaveBar() {
    if (bar || window !== window.top) return
    const p = await send({ type: 'pending' })
    const info = p?.data
    if (!info) return
    const host = document.createElement('div')
    host.setAttribute('data-thevault', '')
    const root = host.attachShadow({ mode: 'closed' }) // page scripts cannot reach inside
    const css = new CSSStyleSheet()
    css.replaceSync(`
      :host { all: initial; }
      .bar { position: fixed; top: 12px; right: 12px; z-index: 2147483647; width: min(360px, calc(100vw - 24px)); font: 14px/1.45 system-ui, sans-serif;
        background: #0e1522; color: #e7ecf5; border: 1px solid #2b3b59; border-radius: 12px; box-shadow: 0 12px 40px rgba(0,0,0,.45); padding: 14px; }
      .row { display: flex; gap: 10px; align-items: center; }
      img { width: 28px; height: 28px; }
      strong { display: block; } span.s { color: #9fb0c9; font-size: 13px; word-break: break-all; }
      .btns { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
      button { font: inherit; cursor: pointer; border-radius: 8px; border: 1px solid #2b3b59; background: #121b2b; color: #e7ecf5; padding: 6px 12px; }
      button.p { background: #5b9bff; border-color: #5b9bff; color: #04101f; font-weight: 600; }
      button:focus-visible { outline: 2px solid #8bb8ff; outline-offset: 2px; }
      .msg { margin-top: 8px; color: #f5b04a; font-size: 13px; }
    `)
    root.adoptedStyleSheets = [css]
    const el = (tag, props = {}, ...kids) => { const e = document.createElement(tag); Object.assign(e, props); e.append(...kids); return e }
    const msg = el('div', { className: 'msg', role: 'status' })
    const act = async (action) => {
      const r = await send({ type: 'promptAction', action })
      if (r?.data?.ok || action === 'dismiss' || action === 'never') return close()
      msg.textContent = r?.data?.message || r?.error?.message || 'That did not work.'
    }
    const btn = (label, action, cls) => { const b = el('button', { type: 'button', className: cls || '', textContent: label }); b.addEventListener('click', (ev) => { if (ev.isTrusted) act(action) }); return b }
    const close = () => { host.remove(); bar = null }
    const verb = info.kind === 'update' ? 'Update the password for' : 'Save the login for'
    root.append(el('div', { className: 'bar', role: 'alertdialog', ariaLabel: 'TheVault: save this login?' },
      el('div', { className: 'row' }, el('img', { src: chrome.runtime.getURL('icons/icon-48.png'), alt: '' }),
        el('div', {}, el('strong', { textContent: `${verb} ${info.host}?` }), el('span', { className: 's', textContent: info.username || '(no username)' }))),
      el('div', { className: 'btns' }, btn(info.kind === 'update' ? 'Update' : 'Save', 'save', 'p'), btn('Not now', 'dismiss'), btn('Never for this site', 'never')),
      info.locked ? el('div', { className: 'msg', textContent: 'TheVault is locked: click the toolbar icon to unlock, then press Save.' }) : null, msg))
    bar = host
    document.documentElement.append(host)
    setTimeout(() => { if (bar === host) close() }, 45000)
  }

})()
