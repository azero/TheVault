// A quick, honest strength estimate for the UI. It is a heuristic (pool size x length, minus penalties for common
// patterns), not a guarantee: a long random password from the generator is the real answer.
const COMMON = new Set(('123456 password 123456789 12345678 12345 qwerty abc123 password1 111111 iloveyou admin welcome letmein monkey dragon ' +
  'football baseball master sunshine princess login passw0rd 1234567 123123 000000 qwertyuiop 1q2w3e4r zaq12wsx trustno1 changeme ' +
  'summer winter spring autumn secret hello freedom whatever shadow michael jordan superman batman starwars company123').split(' '))

export function estimateStrength(pw) {
  if (!pw) return { bits: 0, score: 0, label: 'Empty' }
  let pool = 0
  if (/[a-z]/.test(pw)) pool += 26
  if (/[A-Z]/.test(pw)) pool += 26
  if (/\d/.test(pw)) pool += 10
  if (/[^A-Za-z0-9]/.test(pw)) pool += 32
  let bits = pw.length * Math.log2(Math.max(pool, 2))
  const lower = pw.toLowerCase()
  if (COMMON.has(lower) || COMMON.has(lower.replace(/\d+$/, ''))) bits = Math.min(bits, 12)
  const uniq = new Set(pw).size
  if (uniq < pw.length / 2) bits *= 0.6 // heavy repetition
  if (/(.)\1{2,}/.test(pw)) bits -= 8
  if (/(?:abc|bcd|cde|def|123|234|345|456|567|678|789|qwe|wer|asd|sdf|zxc)/i.test(pw)) bits -= 10
  if (/^[A-Za-z]+\d{1,4}[!@#$%^&*.]?$/.test(pw)) bits -= 12 // Word123!
  bits = Math.max(0, Math.round(bits))
  const score = bits < 28 ? 0 : bits < 45 ? 1 : bits < 64 ? 2 : bits < 90 ? 3 : 4
  return { bits, score, label: ['Very weak', 'Weak', 'Fair', 'Strong', 'Excellent'][score] }
}
