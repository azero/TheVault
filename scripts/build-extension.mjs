// Packages extension/ into dist/thevault-extension.zip (and, for the Docker build, server/internal/web/static/downloads/).
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')
execFileSync('node', [path.join(root, 'scripts/sync-core.mjs')], { stdio: 'inherit' })
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'extension/manifest.json'), 'utf8'))
const out = path.join(root, 'dist')
fs.mkdirSync(out, { recursive: true })
const zip = path.join(out, `thevault-extension-${manifest.version}.zip`)
fs.rmSync(zip, { force: true })
execFileSync('zip', ['-r', '-q', '-X', zip, '.', '-x', '*.DS_Store', '-x', 'README.md'], { cwd: path.join(root, 'extension'), stdio: 'inherit' })
console.log('wrote', path.relative(root, zip), (fs.statSync(zip).size / 1024).toFixed(0) + ' KB')
if (process.argv.includes('--embed')) {
  const dl = path.join(root, 'server/internal/web/static/downloads')
  fs.mkdirSync(dl, { recursive: true })
  fs.copyFileSync(zip, path.join(dl, 'thevault-extension.zip'))
  console.log('embedded into the server build')
}
