// Password and passphrase generation from the CSPRNG, with no modulo bias.
import { randomInt } from './crypto.js'
import { WORDS } from './wordlist.js'

const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
}
const AMBIGUOUS = /[O0oIl1|`'"\\]/g

export const DEFAULTS = { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: false }

export function generatePassword(opts = {}) {
  const o = { ...DEFAULTS, ...opts }
  const length = Math.min(128, Math.max(4, Math.floor(o.length)))
  const pools = ['lower', 'upper', 'digits', 'symbols'].filter((k) => o[k]).map((k) => {
    const chars = o.avoidAmbiguous ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]
    return chars
  })
  if (!pools.length) throw new RangeError('Pick at least one kind of character.')
  const all = pools.join('')
  const out = pools.map((p) => p[randomInt(p.length)]) // at least one of each chosen kind
  while (out.length < length) out.push(all[randomInt(all.length)])
  for (let i = out.length - 1; i > 0; i--) { // Fisher-Yates
    const j = randomInt(i + 1);
    [out[i], out[j]] = [out[j], out[i]]
  }
  return out.join('')
}

export function generatePassphrase({ words = 5, separator = '-', capitalize = false, number = false } = {}) {
  const n = Math.min(12, Math.max(3, Math.floor(words)))
  const picked = Array.from({ length: n }, () => {
    const w = WORDS[randomInt(WORDS.length)]
    return capitalize ? w[0].toUpperCase() + w.slice(1) : w
  })
  if (number) picked[randomInt(n)] += String(randomInt(10))
  return picked.join(separator)
}

/** Entropy in bits of what the options can produce (for the UI hint). */
export function passwordEntropy(opts = {}) {
  const o = { ...DEFAULTS, ...opts }
  let pool = 0
  for (const k of ['lower', 'upper', 'digits', 'symbols']) if (o[k]) pool += (o.avoidAmbiguous ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]).length
  return pool ? Math.floor(o.length * Math.log2(pool)) : 0
}
export const passphraseEntropy = ({ words = 5, number = false } = {}) => Math.floor(words * Math.log2(WORDS.length) + (number ? Math.log2(10 * words) : 0))
