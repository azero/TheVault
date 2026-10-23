// Password / passphrase generator: a page of its own, and a popover used by the item editor.
import { h, icon } from './dom.js'
import { generatePassword, generatePassphrase, passwordEntropy, passphraseEntropy } from '../core/generator.js'
import { estimateStrength } from '../core/strength.js'
import { copy } from './clipboard.js'
import { colorGenerated, pageHead } from './components.js'
import { prefs } from './prefs.js'

function load() { try { return JSON.parse(localStorage.getItem('vault-gen') || '{}') } catch { return {} } }
function save(o) { try { localStorage.setItem('vault-gen', JSON.stringify(o)) } catch { /* ignore */ } }

/** The controls and output. onUse(pw) adds a "Use this" button (editor popover). */
export function generatorPanel({ onUse } = {}) {
  const o = { mode: 'password', length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: false, words: 5, separator: '-', capitalize: false, number: false, ...load() }
  const out = h('div', { class: 'gen-out', 'aria-live': 'polite', 'data-testid': 'gen-out' })
  const info = h('div', { class: 'muted small' })
  let current = ''
  const root = h('div', { class: 'stack' })

  const regen = () => {
    try {
      current = o.mode === 'password'
        ? generatePassword(o)
        : generatePassphrase({ words: o.words, separator: o.separator, capitalize: o.capitalize, number: o.number })
      out.replaceChildren(colorGenerated(current))
      const bits = o.mode === 'password' ? passwordEntropy(o) : passphraseEntropy(o)
      info.textContent = `${bits} bits of entropy · ${estimateStrength(current).label}`
    } catch (e) { current = ''; out.textContent = ''; info.textContent = e.message }
    const { mode, length, lower, upper, digits, symbols, avoidAmbiguous, words, separator, capitalize, number } = o
    save({ mode, length, lower, upper, digits, symbols, avoidAmbiguous, words, separator, capitalize, number })
  }

  const check = (key, label) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: o[key], on: { change: (e) => { o[key] = e.target.checked; regen() } } }), label)
  const range = (key, label, min, max, id) => {
    const val = h('span', { class: 'mono' }, String(o[key]))
    const input = h('input', { type: 'range', id, min, max, value: String(o[key]), on: { input: (e) => { o[key] = Number(e.target.value); val.textContent = e.target.value; regen() } } })
    return h('div', { class: 'field' }, h('label', { class: 'label', for: id }, label, ' ', val), input)
  }
  const pwOpts = h('div', { class: 'stack-sm' }, range('length', 'Length', 8, 64, 'g-len'), h('div', { class: 'row' }, check('lower', 'a–z'), check('upper', 'A–Z'), check('digits', '0–9'), check('symbols', '!@#$')), check('avoidAmbiguous', 'Avoid look-alike characters (O 0 l 1)'))
  const sep = h('input', { class: 'input', id: 'g-sep', maxlength: 3, value: o.separator, on: { input: (e) => { o.separator = e.target.value; regen() } } })
  const ppOpts = h('div', { class: 'stack-sm' }, range('words', 'Words', 3, 10, 'g-words'), h('div', { class: 'field' }, h('label', { class: 'label', for: 'g-sep' }, 'Separator'), sep), h('div', { class: 'row' }, check('capitalize', 'Capitalize'), check('number', 'Add a number')))
  const show = () => { pwOpts.classList.toggle('hidden', o.mode !== 'password'); ppOpts.classList.toggle('hidden', o.mode !== 'passphrase') }
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Type' })
  const drawSeg = () => seg.replaceChildren(...[['password', 'Password'], ['passphrase', 'Passphrase']].map(([m, l]) => h('button', { type: 'button', 'aria-pressed': String(o.mode === m), on: { click: () => { o.mode = m; drawSeg(); show(); regen() } } }, l)))
  drawSeg(); show()

  const actions = h('div', { class: 'cluster' },
    h('button', { class: 'btn btn-sm', type: 'button', on: { click: regen } }, icon('refresh', 'icon-sm'), 'Regenerate'),
    h('button', { class: 'btn btn-sm', type: 'button', on: { click: () => current && copy(current, 'Password copied') } }, icon('copy', 'icon-sm'), 'Copy'),
    onUse ? h('button', { class: 'btn btn-primary btn-sm', type: 'button', on: { click: () => current && onUse(current) } }, 'Use this') : null)
  root.append(seg, out, info, actions, pwOpts, ppOpts)
  regen()
  return { el: root, current: () => current }
}

export function generatorView() {
  const p = generatorPanel()
  return h('div', { class: 'stack' }, pageHead('Generator', 'Random passwords and passphrases from your browser’s secure random number generator. Nothing is sent anywhere.'),
    h('div', { class: 'card' }, h('div', { class: 'card-body' }, p.el)))
}

export { prefs }
