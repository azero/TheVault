// The signed-in, unlocked application: top bar, sidebar, routed content.
import { h, icon, mount, avatarClass, initials, debounce, toast } from './dom.js'
import { post } from './api.js'
import { vault, lock, counts, folders, isAdmin, subscribe, spaceName } from './vault.js'
import { navigate, onRoute, parse, href } from './router.js'
import { TYPES } from '../core/item.js'
import { prefs, applyTheme } from './prefs.js'
import { listView } from './list.js'
import { editorView } from './editor.js'
import { generatorView } from './generator.js'
import { healthView } from './health.js'
import { settingsView } from './settings.js'
import { spaceManageView } from './spaces.js'
import { adminView } from './admin.js'

export const ui = { query: '', sort: prefs.get('sort') }

export function startShell(root) {
  const cleanups = []
  const content = h('main', { class: 'content', id: 'main', tabindex: '-1' })
  const side = h('nav', { class: 'sidebar', id: 'sidebar', 'aria-label': 'Main' })
  const search = h('input', { class: 'input', id: 'search', type: 'search', placeholder: 'Search your vault', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Search your vault' })
  const menu = h('div', { class: 'menu hidden', id: 'acct-menu', role: 'menu' })
  const acctBtn = h('button', { class: 'btn btn-ghost btn-icon', type: 'button', 'aria-haspopup': 'menu', 'aria-expanded': 'false', 'aria-controls': 'acct-menu', title: 'Account' })

  const closeMenu = () => { menu.classList.add('hidden'); acctBtn.setAttribute('aria-expanded', 'false') }
  const u = vault.me
  acctBtn.append(h('span', { class: `avatar avatar-sm ${avatarClass(u.sub)}${isAdmin() ? ' is-admin' : ''}` }, initials(u.name || u.email)))
  const theme = () => {
    const cur = prefs.get('theme')
    const next = cur === 'dark' ? 'light' : cur === 'light' ? 'auto' : 'dark'
    prefs.set('theme', next); applyTheme(next); toast(next === 'auto' ? 'Theme follows your system' : `${next[0].toUpperCase()}${next.slice(1)} theme`); closeMenu()
  }
  menu.append(
    h('div', { class: 'menu-head' }, h('strong', {}, u.name || u.email), h('span', { class: 'muted small' }, u.email), isAdmin() ? h('span', { class: 'badge badge-gold' }, 'Administrator') : null),
    h('a', { href: href('/settings/account'), role: 'menuitem', on: { click: closeMenu } }, icon('settings'), 'Settings'),
    h('button', { type: 'button', role: 'menuitem', on: { click: theme } }, icon('sun'), 'Switch theme'),
    h('button', { type: 'button', role: 'menuitem', on: { click: () => { closeMenu(); lock() } } }, icon('lock'), 'Lock vault'),
    h('hr'),
    h('button', { type: 'button', role: 'menuitem', on: { click: async () => { try { const r = await post('/session/logout'); location.assign(r.redirect) } catch { location.assign('/login') } } } }, icon('logout'), 'Sign out'))
  acctBtn.addEventListener('click', () => {
    const open = menu.classList.toggle('hidden') === false
    acctBtn.setAttribute('aria-expanded', String(open))
    if (open) menu.querySelector('a,button')?.focus()
  })
  document.addEventListener('click', (e) => { if (!menu.contains(e.target) && !acctBtn.contains(e.target)) closeMenu() })
  menu.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeMenu(); acctBtn.focus() } })

  const navBtn = h('button', { class: 'btn btn-ghost btn-icon menu-btn', type: 'button', 'aria-label': 'Menu', 'aria-controls': 'sidebar', 'aria-expanded': 'false', on: { click: () => toggleNav() } }, icon('menu'))
  const toggleNav = (open) => {
    const next = open ?? !document.body.classList.contains('nav-open')
    document.body.classList.toggle('nav-open', next)
    navBtn.setAttribute('aria-expanded', String(next))
  }
  const bar = h('header', { class: 'topbar' },
    navBtn,
    h('a', { class: 'brand', href: href('/all'), 'aria-label': 'TheVault home' }, h('img', { src: '/static/brand/thevault-logo-nav.webp', width: 240, height: 80, alt: 'TheVault' }), h('img', { class: 'brand-mark', src: '/static/brand/mark.png', width: 96, height: 96, alt: 'TheVault' })),
    h('div', { class: 'search' }, icon('search'), search, h('kbd', { class: 'kbd', 'aria-hidden': 'true' }, '/')),
    h('div', { class: 'spacer' }),
    h('a', { class: 'btn btn-primary btn-sm', href: href('/new/login') }, icon('plus', 'icon-sm'), h('span', {}, 'New item')),
    h('button', { class: 'btn btn-ghost btn-icon', type: 'button', title: 'Lock vault (Alt+L)', 'aria-label': 'Lock vault', on: { click: () => lock() } }, icon('lock')),
    h('div', { class: 'menu-wrap' }, acctBtn, menu))

  root.className = 'app-root'
  mount(root, bar, h('div', { class: 'app-main' }, side, content), h('div', { class: 'drawer-scrim', on: { click: () => toggleNav(false) } }))
  document.body.classList.add('app-body')

  const renderSide = (route) => {
    const c = counts()
    const link = (label, ic, to, count, current) => h('a', { class: 'nav-link', href: to, 'aria-current': current ? 'page' : null, on: { click: () => toggleNav(false) } }, icon(ic), h('span', { class: 'truncate' }, label), count != null ? h('span', { class: 'count' }, String(count)) : null)
    const seg = route.seg
    const is = (a, b) => seg[0] === a && (b === undefined || seg[1] === b)
    const groups = [
      h('div', { class: 'nav-group' }, h('div', { class: 'nav-title' }, 'Vault'),
        link('All items', 'vault', href('/all'), c.all, is('all')), link('Favorites', 'star', href('/fav'), c.fav, is('fav'))),
      h('div', { class: 'nav-group' }, h('div', { class: 'nav-title' }, 'Types'),
        ...Object.entries(TYPES).map(([k, t]) => link(t.plural, t.icon, href('/type/' + k), c.types[k] ?? 0, is('type', k)))),
    ]
    const fl = folders()
    if (fl.length) groups.push(h('div', { class: 'nav-group' }, h('div', { class: 'nav-title' }, 'Folders'), ...fl.map(([name, n]) => link(name, 'folder', href('/folder/' + encodeURIComponent(name)), n, is('folder', name)))))
    groups.push(h('div', { class: 'nav-group' }, h('div', { class: 'nav-title' }, 'Spaces', h('span', { class: 'spacer' }), h('a', { class: 'btn btn-ghost btn-icon btn-sm', href: href('/spaces'), title: 'Manage spaces', 'aria-label': 'Manage spaces' }, icon('plus', 'icon-sm'))),
      ...[...vault.spaces.values()].map((s) => link(s.name, 'users', href('/space/' + s.id), c.spaces[s.id] ?? 0, is('space', s.id))),
      vault.spaces.size === 0 ? h('p', { class: 'muted small' }, 'Share items with your team in a space.') : null))
    groups.push(h('div', { class: 'nav-group' }, h('div', { class: 'nav-title' }, 'Tools'),
      link('Generator', 'wand', href('/generator'), null, is('generator')), link('Password health', 'pulse', href('/health'), null, is('health')), link('Trash', 'trash', href('/trash'), c.trash, is('trash')),
      link('Settings', 'settings', href('/settings/account'), null, is('settings'))))
    if (isAdmin()) groups.push(h('div', { class: 'nav-group' }, h('div', { class: 'nav-title' }, 'Administration'), link('Admin', 'dashboard', href('/admin/overview'), null, is('admin'))))
    mount(side, ...groups)
  }

  const render = async (route) => {
    cleanups.splice(0).forEach((f) => f())
    toggleNav(false)
    renderSide(route)
    const ctx = { route, onCleanup: (f) => cleanups.push(f), refreshSide: () => renderSide(parse()) }
    const [a] = route.seg
    let node
    try {
      if (a === 'new') node = editorView(ctx, { mode: 'new', type: route.seg[1], vaultId: route.query.vault })
      else if (a === 'edit') node = editorView(ctx, { mode: 'edit', id: route.seg[1] })
      else if (a === 'generator') node = generatorView(ctx)
      else if (a === 'health') node = healthView(ctx)
      else if (a === 'settings') node = settingsView(ctx)
      else if (a === 'spaces' || a === 'space-manage') node = spaceManageView(ctx)
      else if (a === 'admin') node = adminView(ctx)
      else node = listView(ctx, ui)
      node = await node
    } catch (e) {
      node = h('div', { class: 'alert alert-error', role: 'alert' }, icon('alert'), h('div', {}, e.message || 'This page could not be shown.'))
    }
    content.classList.toggle('panes-wrap', a === undefined || ['all', 'fav', 'type', 'folder', 'space', 'trash'].includes(a))
    mount(content, node)
  }

  const refreshList = debounce(() => { const r = parse(); if (!['all', 'fav', 'type', 'folder', 'space', 'trash'].includes(r.seg[0])) navigate('/all'); else render(r) }, 120)
  search.addEventListener('input', () => { ui.query = search.value; refreshList() })
  search.addEventListener('keydown', (e) => { if (e.key === 'Escape') { search.value = ''; ui.query = ''; refreshList(); search.blur() } })
  const keys = (e) => {
    const tag = (e.target.tagName || '').toLowerCase()
    if (e.key === '/' && !['input', 'textarea', 'select'].includes(tag) && !e.target.isContentEditable) { e.preventDefault(); search.focus() }
    if (e.altKey && e.key.toLowerCase() === 'l') { e.preventDefault(); lock() }
  }
  document.addEventListener('keydown', keys)

  const offRoute = onRoute(render)
  const offVault = subscribe((what) => { if (what === 'sync' || what === 'spaces') render(parse()) })
  render(parse())
  return () => {
    offRoute(); offVault(); document.removeEventListener('keydown', keys); cleanups.splice(0).forEach((f) => f())
    document.body.classList.remove('app-body', 'nav-open')
  }
}
