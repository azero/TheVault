import { h, icon } from './dom.js'
import { healthReport, spaceName } from './vault.js'
import { href } from './router.js'
import { pageHead, spinner, itemAvatar } from './components.js'
import { parseUrl } from '../core/urlmatch.js'

export async function healthView(ctx) {
  const box = h('div', {}, spinner('Checking your passwords on this device…'))
  const rep = await healthReport()
  const sections = [
    ['weak', 'Weak passwords', 'Easy to guess. Replace them with generated ones.', rep.weak, 'bad'],
    ['reused', 'Reused passwords', 'The same password protects more than one login.', rep.reused, 'bad'],
    ['insecure', 'Unencrypted websites', 'Saved with an http:// address. TheVault will not autofill on those.', rep.insecure, 'warn'],
    ['old', 'Old passwords', 'Not changed in over a year.', rep.old, 'warn'],
    ['expiring', 'API keys expiring', 'Expired or expiring within 30 days.', rep.expiring, 'bad'],
    ['noTotp', 'No one-time password', 'Logins with no 2-step code saved. Turn on 2-step verification where the site offers it.', rep.noTotp, 'warn'],
  ]
  let open = sections.find((s) => s[3].length)?.[0] ?? null
  const render = () => {
    const grid = h('div', { class: 'health-grid' }, sections.map(([key, title, , rows, tone]) => h('button', { class: `health-card ${rows.length ? tone : 'ok'}`, type: 'button', 'aria-pressed': String(open === key), on: { click: () => { open = key; render() } } },
      h('span', { class: 'n' }, String(rows.length)), h('span', {}, h('strong', {}, title), h('div', { class: 'muted small' }, rows.length ? 'Needs attention' : 'All good')))))
    const sel = sections.find((s) => s[0] === open)
    const detail = sel ? h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', {}, sel[1]), h('span', { class: 'muted small' }, sel[2])),
      sel[3].length ? h('ul', { class: 'items' }, [...new Map(sel[3].map((e) => [e.id, e])).values()].map((e) => h('li', {}, h('a', { class: 'item-row', href: href('/all/item/' + e.id) }, itemAvatar(e.item),
        h('span', { class: 'meta' }, h('span', { class: 'title truncate' }, e.item.name), h('span', { class: 'sub truncate' }, e.item.data.username || parseUrl(e.item.urls[0]?.url)?.host || spaceName(e.vaultId))), icon('chevron-right'))))) : h('div', { class: 'card-body muted' }, 'Nothing to fix here.')) : null
    box.replaceChildren(grid, detail)
  }
  render()
  return h('div', {}, pageHead('Password health', `Checked ${rep.total} item${rep.total === 1 ? '' : 's'} on this device. Nothing about your passwords is sent anywhere.`), box)
}
