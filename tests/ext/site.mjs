// A throwaway website with the login forms a password manager meets in the wild (and a few hostile ones).
import http from 'node:http'

const FORM = (extra = '') => `<form id="f" method="post" action="/submit"><label>User <input id="u" name="username" autocomplete="username"></label>
<label>Password <input id="p" name="password" type="password" autocomplete="current-password"></label>${extra}<button id="go" type="submit">Sign in</button></form>`
const page = (body, head = '') => `<!doctype html><meta charset="utf-8"><title>test site</title>${head}<body>${body}</body>`

export function startSite(port = 0) {
  let frameTarget = ''
  const routes = {
    '/login.html': () => page(FORM()),
    // honeypot fields a phishing page might add: invisible to the person, visible to a naive form filler
    '/hidden.html': () => page(`<form id="f" method="post" action="/submit">
      <input id="hp-u" name="email" style="display:none"><input id="hp-p" type="password" name="pw2" style="position:absolute;left:-9999px">
      <input id="hp-o" type="password" name="pw3" style="opacity:0">
      <label>User <input id="u" name="username"></label><label>Password <input id="p" name="password" type="password"></label><button type="submit">Go</button></form>`),
    '/stepped.html': () => page(`<form id="f" action="/stepped2.html"><label>Email <input id="u" type="email" name="email" autocomplete="username"></label><button type="submit">Next</button></form>`),
    '/frame-host.html': () => page(`<h1>embeds a login</h1><iframe id="fr" src="${frameTarget}" width="500" height="300"></iframe>`),
    '/with-frame.html': () => page(FORM() + `<iframe id="fr" src="${frameTarget}" width="500" height="300"></iframe>`),
    '/spa.html': () => page(FORM(), `<script src="/spa.js"></script>`),
    '/spa.js': () => ['text/javascript', `document.addEventListener('DOMContentLoaded',()=>{document.getElementById('f').addEventListener('submit',e=>{e.preventDefault();document.title='submitted'})})`],
    '/submit': () => page('<h1 id="done">Welcome</h1>'),
    '/otp.html': () => page(`<form id="f"><label>Code <input id="otp" autocomplete="one-time-code"></label></form>`),
  }
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x')
    const r = routes[u.pathname]
    if (!r) { res.writeHead(404); return res.end() }
    const out = r()
    const [type, body] = Array.isArray(out) ? out : ['text/html', out]
    res.writeHead(200, { 'Content-Type': type })
    res.end(body)
  })
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve({
    port: server.address().port, setFrameTarget: (u) => { frameTarget = u }, close: () => new Promise((r) => server.close(r)),
  })))
}
