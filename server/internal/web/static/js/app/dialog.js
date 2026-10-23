import { h, icon } from './dom.js'

/** Modal built on <dialog>: focus trap, Esc to close and backdrop come from the platform. */
export function modal({ title, body, actions }) {
  return new Promise((resolve) => {
    const dlg = h('dialog', { 'aria-labelledby': 'dlg-title' })
    const done = (v) => { if (dlg.open) dlg.close(); dlg.remove(); resolve(v) }
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); done(undefined) })
    dlg.addEventListener('click', (e) => { if (e.target === dlg) done(undefined) })
    const foot = h('div', { class: 'dlg-foot' }, actions(done))
    dlg.append(h('div', { class: 'dlg-body' }, h('h2', { id: 'dlg-title' }, title), body), foot)
    document.body.append(dlg)
    dlg.showModal()
    const first = dlg.querySelector('input:not([type=hidden]), textarea, select')
    ;(first || dlg.querySelector('.btn-primary, .btn-danger'))?.focus()
  })
}

export function confirmDialog({ title, body, confirm = 'Confirm', danger = false, cancel = 'Cancel' }) {
  return modal({
    title, body: h('div', {}, typeof body === 'string' ? h('p', body) : body),
    actions: (done) => [
      h('button', { class: 'btn', type: 'button', on: { click: () => done(false) } }, cancel),
      h('button', { class: 'btn ' + (danger ? 'btn-danger' : 'btn-primary'), type: 'button', on: { click: () => done(true) } }, confirm),
    ],
  }).then((v) => v === true)
}

/** Ask for the master password again before something dangerous. Resolves with the password or null. */
export function passwordDialog({ title, body, confirm = 'Continue', danger = false, verify }) {
  const input = h('input', { class: 'input', type: 'password', id: 'pw-confirm', autocomplete: 'current-password', required: true })
  const err = h('p', { class: 'alert alert-error hidden', role: 'alert' })
  return modal({
    title,
    body: h('form', { on: { submit: (e) => e.preventDefault() } }, h('p', body), h('div', { class: 'field' }, h('label', { class: 'label', for: 'pw-confirm' }, 'Master password'), input), err),
    actions: (done) => {
      const btn = h('button', { class: 'btn ' + (danger ? 'btn-danger' : 'btn-primary'), type: 'submit' }, confirm)
      const go = async () => {
        if (!input.value) return
        btn.disabled = true
        try {
          if (verify) await verify(input.value)
          done(input.value)
        } catch (e) {
          err.classList.remove('hidden'); err.textContent = e.message; btn.disabled = false; input.select()
        }
      }
      input.form.addEventListener('submit', go)
      btn.addEventListener('click', (e) => { e.preventDefault(); go() })
      return [h('button', { class: 'btn', type: 'button', on: { click: () => done(null) } }, 'Cancel'), btn]
    },
  }).then((v) => v ?? null)
}

export function infoDialog({ title, body, ok = 'Close' }) {
  return modal({ title, body, actions: (done) => [h('button', { class: 'btn btn-primary', type: 'button', on: { click: () => done(true) } }, ok)] })
}

export const alertBox = (kind, text, extra) => h('div', { class: 'alert alert-' + kind, role: kind === 'error' ? 'alert' : 'status' },
  icon(kind === 'error' || kind === 'warn' ? 'alert' : kind === 'success' ? 'check' : 'info'), h('div', {}, text, extra))
