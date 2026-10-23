import test from 'node:test'
import assert from 'node:assert/strict'
import { isFillableOrigin, matchItems, matchScore, parseUrl } from '../../server/internal/web/static/js/core/urlmatch.js'

const R = (url, match = 'host') => ({ url, match })

test('exact host matching, https only', () => {
  assert.ok(matchScore(R('https://example.com'), 'https://example.com/login?x=1'))
  assert.ok(matchScore(R('example.com'), 'https://EXAMPLE.com./'))
  assert.equal(matchScore(R('https://example.com'), 'http://example.com/'), 0, 'downgraded page')
  assert.equal(matchScore(R('https://example.com'), 'https://login.example.com/'), 0, 'subdomain needs domain mode')
  assert.equal(matchScore(R('https://example.com'), 'https://example.com:8443/'), 0, 'different port')
})

test('phishing look-alikes never match', () => {
  const rule = R('https://paypal.com', 'domain')
  for (const page of [
    'https://paypal.com.evil.io/', 'https://evil.io/paypal.com', 'https://evilpaypal.com/', 'https://paypal.co/', 'https://paypa1.com/',
    'https://paypal.com@evil.io/', 'https://xn--pypal-4ve.com/', 'https://paypal-com.evil.io/', 'javascript:alert(1)', 'data:text/html,x', 'ftp://paypal.com/',
    'https://evil.io/?u=https://paypal.com', 'https://notpaypal.com/', 'https://paypal.com:444/',
  ]) assert.equal(matchScore(rule, page), 0, page)
  assert.ok(matchScore(rule, 'https://www.paypal.com/signin'))
  assert.ok(matchScore(rule, 'https://a.b.paypal.com/'))
})

test('domain mode: boundary is the saved host; IPs and bare TLDs never expand', () => {
  assert.equal(matchScore(R('com', 'domain'), 'https://evil.com/'), 0)
  assert.equal(matchScore(R('10.0.0.1', 'domain'), 'https://1.10.0.0.1/'), 0)
  assert.equal(matchScore(R('https://[::1]', 'domain'), 'http://[::1]/'), 0, 'a saved https rule never matches an http page')
  assert.equal(matchScore(R('http://[::1]', 'domain'), 'http://[::1]/'), 3)
})

test('exact mode needs the same origin and a path prefix', () => {
  assert.ok(matchScore(R('https://a.com/admin', 'exact'), 'https://a.com/admin/users'))
  assert.equal(matchScore(R('https://a.com/admin', 'exact'), 'https://a.com/other'), 0)
  assert.equal(matchScore(R('https://a.com/admin', 'exact'), 'https://www.a.com/admin'), 0)
})

test('never mode and bad rules', () => {
  assert.equal(matchScore(R('https://a.com', 'never'), 'https://a.com/'), 0)
  for (const bad of ['', 'http://', 'https://user:pw@a.com', 'ftp://a.com', 'x'.repeat(3000)]) assert.equal(matchScore(R(bad), 'https://a.com/'), 0, bad)
  assert.equal(parseUrl('https://user:pw@a.com'), null)
})

test('http only for loopback, or when the user saved http themselves', () => {
  assert.ok(isFillableOrigin('http://localhost:3000/'))
  assert.ok(isFillableOrigin('http://127.0.0.1/'))
  assert.ok(!isFillableOrigin('http://intranet.corp/'))
  assert.equal(matchScore(R('http://intranet.corp'), 'http://intranet.corp/'), 0, 'plain http pages are never filled, even if saved')
  assert.ok(matchScore(R('http://localhost:3000'), 'http://localhost:3000/login'))
  assert.equal(matchScore(R('http://localhost:3000'), 'http://localhost:4000/'), 0)
  assert.ok(matchScore(R('http://localhost'), 'https://localhost/'), 'saved http rule also matches https of the same host')
})

test('matchItems sorts by score, then favourites', () => {
  const mk = (name, url, match, fav = false) => ({ id: name, name, fav, urls: [{ url, match }] })
  const out = matchItems([mk('sub', 'https://a.com', 'domain'), mk('exact', 'https://www.a.com/x', 'exact'), mk('host', 'https://www.a.com', 'host', true), mk('other', 'https://b.com', 'host')], 'https://www.a.com/x/y')
  assert.deepEqual(out.map((i) => i.name), ['exact', 'host', 'sub'])
})

test('ports, path boundaries and shared suffixes', () => {
  const m = (url, page, match = 'host') => matchScore({ url, match }, page)
  assert.equal(m('https://example.com', 'https://example.com:80/'), 0, 'a TLS rule never meets another service on :80')
  assert.equal(m('http://localhost', 'http://localhost:443'), 0)
  assert.equal(m('https://example.com:80', 'https://example.com/'), 0)
  assert.ok(m('http://example.com', 'https://example.com/') > 0, 'an old http rule still meets the https site')
  assert.equal(m('https://example.com/app', 'https://example.com/apple', 'exact'), 0)
  assert.equal(m('https://example.com/app', 'https://example.com/app-evil/x', 'exact'), 0)
  assert.ok(m('https://example.com/app', 'https://example.com/app', 'exact') > 0)
  assert.ok(m('https://example.com/app', 'https://example.com/app/x', 'exact') > 0)
  assert.equal(m('https://github.io', 'https://evil.github.io/', 'domain'), 0, 'a domain rule on a shared suffix would cover every tenant')
  assert.equal(m('https://co.uk', 'https://evil.co.uk/', 'domain'), 0)
  assert.ok(m('https://example.co.uk', 'https://app.example.co.uk/', 'domain') > 0)
})
