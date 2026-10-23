import { startStack } from './devserver.mjs'
import { launch, person, shot, signInAndSetup } from './lib.mjs'

const stack = await startStack()
const browser = await launch()
try {
  const ana = await person(browser, stack, 'ana')
  const p = ana.page
  await p.goto(stack.url + '/login')
  await shot(p, 'smoke-login')
  const key = await signInAndSetup(p, stack)
  console.log('recovery key', key)
  await shot(p, 'smoke-empty-vault')
  console.log('problems:', ana.problems)
} finally {
  await browser.close(); await stack.stop()
}
