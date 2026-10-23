// Which saved items may be offered for a page? Deliberately strict: a phishing page must never match.
//  host   (default) the page host equals the saved host (and port)
//  domain the page host equals the saved host or is a subdomain of it (the user's saved host sets the boundary)
//  exact  same origin and the page path starts with the saved path
//  never  never offered
// https is required, except for http://localhost, 127.0.0.1 and [::1], and for rules the user saved as http:// themselves.

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]'])
const isIp = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith('[')

export function parseUrl(text) {
  let s = String(text ?? '').trim()
  if (!s || s.length > 2000) return null
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s
  let u
  try { u = new URL(s) } catch { return null }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null
  if (u.username || u.password || !u.hostname) return null
  const host = u.hostname.toLowerCase().replace(/\.$/, '')
  const port = u.port || (u.protocol === 'https:' ? '443' : '80')
  return { scheme: u.protocol.slice(0, -1), host, port, path: u.pathname || '/', origin: `${u.protocol}//${host}:${port}` }
}

/** May credentials be put into a page at all? */
export function isFillableOrigin(pageUrl) {
  const p = parseUrl(pageUrl)
  return !!p && (p.scheme === 'https' || LOOPBACK.has(p.host))
}

/** 0 = no match; higher is a better match. */
export function matchScore(rule, pageUrl) {
  const page = parseUrl(pageUrl)
  if (!page || !isFillableOrigin(pageUrl) || !rule || rule.match === 'never') return 0
  const saved = parseUrl(rule.url)
  if (!saved) return 0
  // A saved https rule never matches an http page; a saved http rule matches only http or https of the same host.
  if (saved.scheme === 'https' && page.scheme !== 'https') return 0
  const mode = rule.match || 'host'
  if (saved.port !== page.port && !upgradedDefaults(saved, page)) return 0
  if (mode === 'exact') return saved.host === page.host && pathWithin(saved.path, page.path) ? 4 : 0
  if (saved.host === page.host) return 3
  if (mode === 'domain' && !isIp(saved.host) && saved.host.includes('.') && !SHARED_SUFFIXES.has(saved.host) && page.host.endsWith('.' + saved.host)) return 2
  return 0
}

// The only scheme change we allow is an http rule meeting the https site on the same host: 80 -> 443. Any other pairing of
// the two default ports (an https rule on :80, an http rule on :443) is a different service.
const upgradedDefaults = (saved, page) => saved.scheme === 'http' && page.scheme === 'https' && saved.port === '80' && page.port === '443'

/** `/app` covers `/app` and `/app/...`, never `/apple`. */
const pathWithin = (saved, page) => page === saved || page.startsWith(saved.endsWith('/') ? saved : saved + '/')

// Suffixes under which unrelated parties get their own subdomain. A "domain" rule on one of these would hand a login to every
// tenant. (A full public-suffix list is too big to ship; this covers the common multi-part and hosting suffixes.)
const SHARED_SUFFIXES = new Set(`co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk com.au net.au org.au edu.au gov.au co.nz org.nz net.nz co.jp ne.jp or.jp ac.jp co.kr co.in net.in org.in com.br com.cn com.mx com.ar com.tr com.sg com.hk co.za co.il
github.io gitlab.io herokuapp.com vercel.app netlify.app pages.dev workers.dev web.app firebaseapp.com appspot.com azurewebsites.net cloudfront.net amazonaws.com s3.amazonaws.com elasticbeanstalk.com
blogspot.com wordpress.com myshopify.com onrender.com fly.dev repl.co glitch.me ngrok.io ngrok-free.app trycloudflare.com surge.sh render.com railway.app deno.dev netlify.com weebly.com wixsite.com squarespace.com`.split(/\s+/))

/** Items offered for `pageUrl`, best first. `items` are decrypted items with an `id`. */
export function matchItems(items, pageUrl) {
  const out = []
  for (const it of items) {
    if (!it.urls?.length) continue
    let best = 0
    for (const r of it.urls) best = Math.max(best, matchScore(r, pageUrl))
    if (best > 0) out.push({ item: it, score: best })
  }
  out.sort((a, b) => b.score - a.score || (b.item.fav === true) - (a.item.fav === true) || a.item.name.localeCompare(b.item.name))
  return out.map((o) => o.item)
}

/** For display: "example.com" from a saved address. */
export const displayHost = (u) => parseUrl(u)?.host ?? ''
