// A minimal ClosedDoor look-alike for browser tests: discovery, JWKS, /authorize (code + PKCE S256, prompt=none, RFC 9207 iss),
// /token, /userinfo, /logout. The signed-in person is chosen by the `sso_user` cookie on this origin, so each browser
// context can be a different user without any UI.
import http from 'node:http'
import crypto from 'node:crypto'

export const USERS = {
  ana: { sub: 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1', email: 'ana@example.com', name: 'Ana Admin', roles: ['admin'] },
  bob: { sub: 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2', email: 'bob@example.com', name: 'Bob Builder', roles: [] },
  cat: { sub: 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3', email: 'cat@example.com', name: 'Cat Coder', roles: [] },
}

const b64u = (b) => Buffer.from(b).toString('base64url')

export async function startFakeSso({ port = 0, clientId = 'app_test', clientSecret = 'cds_secret' } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' }
  const codes = new Map()
  const state = { revoked: new Set(), expirySeconds: 3600, log: [] }
  let base = ''

  const sign = (claims) => {
    const head = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'k1' }))
    const body = b64u(JSON.stringify(claims))
    const sig = crypto.sign('sha256', Buffer.from(head + '.' + body), privateKey)
    return head + '.' + body + '.' + b64u(sig)
  }
  const cookieUser = (req) => {
    const m = /(?:^|;\s*)sso_user=([a-z]+)/.exec(req.headers.cookie || '')
    return m && USERS[m[1]] ? m[1] : null
  }
  const body = (req) => new Promise((res) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => res(d)) })

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, base)
    const send = (code, obj, headers = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...headers }); res.end(JSON.stringify(obj)) }
    if (u.pathname === '/.well-known/openid-configuration') {
      return send(200, { issuer: base, authorization_endpoint: base + '/authorize', token_endpoint: base + '/token', userinfo_endpoint: base + '/userinfo', jwks_uri: base + '/jwks.json', end_session_endpoint: base + '/logout',
        id_token_signing_alg_values_supported: ['RS256'], response_types_supported: ['code'], subject_types_supported: ['public'] })
    }
    if (u.pathname === '/jwks.json') return send(200, { keys: [jwk] })
    if (u.pathname === '/authorize') {
      const q = u.searchParams
      const redirect = q.get('redirect_uri')
      if (q.get('client_id') !== clientId || q.get('code_challenge_method') !== 'S256' || !redirect) { res.writeHead(400); return res.end('bad authorize request') }
      const target = new URL(redirect)
      target.searchParams.set('state', q.get('state') || '')
      target.searchParams.set('iss', base)
      const who = cookieUser(req)
      if (!who) {
        if (q.get('prompt') === 'none') target.searchParams.set('error', 'login_required')
        else { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<h1>fake ClosedDoor: no sso_user cookie</h1>') }
      } else {
        const code = 'code_' + crypto.randomBytes(8).toString('hex')
        codes.set(code, { challenge: q.get('code_challenge'), nonce: q.get('nonce'), redirect, who })
        target.searchParams.set('code', code)
      }
      res.writeHead(302, { Location: target.toString() }); return res.end()
    }
    if (u.pathname === '/token' && req.method === 'POST') {
      const form = new URLSearchParams(await body(req))
      let id = form.get('client_id'), secret = form.get('client_secret')
      const basic = /^Basic (.+)$/.exec(req.headers.authorization || '')
      if (basic) [id, secret] = Buffer.from(basic[1], 'base64').toString().split(':').map(decodeURIComponent)
      if (id !== clientId || secret !== clientSecret) return send(401, { error: 'invalid_client' })
      const c = codes.get(form.get('code')); codes.delete(form.get('code'))
      const challenge = b64u(crypto.createHash('sha256').update(form.get('code_verifier') || '').digest())
      if (!c || c.challenge !== challenge || c.redirect !== form.get('redirect_uri')) return send(400, { error: 'invalid_grant' })
      const user = USERS[c.who]; const now = Math.floor(Date.now() / 1000)
      return send(200, { access_token: 'at_' + c.who + '_' + crypto.randomBytes(6).toString('hex'), token_type: 'Bearer', expires_in: state.expirySeconds,
        id_token: sign({ iss: base, sub: user.sub, aud: clientId, iat: now, exp: now + 3600, nonce: c.nonce, email: user.email, name: user.name, roles: user.roles, apps: [{ client_id: 'demo_notes', name: 'Notes', launch_url: 'https://notes.example/' }, { client_id: 'demo_files', name: 'Files', launch_url: 'https://files.example/' }] }) })
    }
    if (u.pathname === '/userinfo') {
      const m = /^Bearer at_([a-z]+)_/.exec(req.headers.authorization || '')
      if (!m || state.revoked.has(m[1])) return send(401, { error: 'invalid_token' })
      return send(200, { sub: USERS[m[1]].sub, roles: USERS[m[1]].roles, apps: [{ client_id: 'demo_notes', name: 'Notes', launch_url: 'https://notes.example/' }] })
    }
    if (u.pathname === '/logout') {
      const to = u.searchParams.get('post_logout_redirect_uri')
      res.writeHead(302, { Location: to || base, 'Set-Cookie': 'sso_user=; Max-Age=0; Path=/' }); return res.end()
    }
    res.writeHead(404); res.end()
  })
  await new Promise((r) => server.listen(port, '127.0.0.1', r))
  base = 'http://127.0.0.1:' + server.address().port
  return { url: base, state, revoke: (n) => state.revoked.add(n), restore: (n) => state.revoked.delete(n), close: () => new Promise((r) => server.close(r)), clientId, clientSecret }
}
