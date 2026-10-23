// The crypto core has one source of truth (server/internal/web/static/js/core). The extension needs its own copy because an
// extension package must be self-contained. `npm run sync` copies it; `npm run check:sync` (CI) fails if they differ.
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')
const src = path.join(root, 'server/internal/web/static/js/core')
const dst = path.join(root, 'extension/core')
const extras = [
  ['server/internal/web/static/icons.svg', 'extension/icons.svg'],
  ['server/internal/web/static/app.css', 'extension/app.css'],
  ['server/internal/web/static/brand/thevault-logo-nav.webp', 'extension/brand/logo-nav.webp'],
  ['server/internal/web/static/brand/mark.png', 'extension/brand/mark.png'],
]
const check = process.argv.includes('--check')
let drift = 0

fs.mkdirSync(dst, { recursive: true })
const pairs = fs.readdirSync(src).filter((f) => f.endsWith('.js')).map((f) => [path.join(src, f), path.join(dst, f)])
for (const [a, b] of extras) pairs.push([path.join(root, a), path.join(root, b)])
for (const [from, to] of pairs) {
  fs.mkdirSync(path.dirname(to), { recursive: true })
  const want = fs.readFileSync(from)
  const have = fs.existsSync(to) ? fs.readFileSync(to) : null
  if (have && Buffer.compare(want, have) === 0) continue
  drift++
  if (check) console.error('out of sync:', path.relative(root, to))
  else fs.writeFileSync(to, want)
}
if (!check) {
  for (const f of fs.readdirSync(dst)) if (!fs.existsSync(path.join(src, f))) fs.unlinkSync(path.join(dst, f)) // removed upstream
  console.log(drift ? `copied ${drift} file(s) into extension/` : 'extension/core already up to date')
} else if (drift) {
  console.error('Run `npm run sync` and commit the result.')
  process.exit(1)
} else console.log('extension core is in sync')
