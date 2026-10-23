# Development

Requirements: Go (the version in `server/go.mod`), Node 22+, Python 3 with Pillow (only to regenerate logos), a Chromium for the browser tests (`npx playwright-core install chromium`, or set `CHROME_PATH`), `zip` (extension package).

```bash
git clone … && cd TheVault
npm install                     # dev tooling only (playwright-core, axe); nothing here ships
cd server && go test -race ./... && cd ..
npm test && npm run check:sync
node tests/ui/run.mjs           # starts the real server + a fake ClosedDoor itself
node tests/ext/run.mjs
```

## Run it locally

```bash
node tests/ui/devserver.mjs      # prints the vault URL and the fake ClosedDoor URL
```
In a browser, set a cookie `sso_user=ana` (admin), `bob` or `cat` on the fake ClosedDoor's origin (DevTools → Application → Cookies, or `document.cookie` on that origin), then open the vault URL. Or run against a real ClosedDoor: register a confidential app with redirect `http://localhost:8444/auth/callback` and start `thevault serve` with the `VAULT_*` variables from [operations.md](operations.md).

## Layout of the server

```
cmd/thevault           serve | healthcheck | backup | version
internal/config        environment -> Config (validated, strict)
internal/store         SQLite (pure Go), append-only migrations, every query; no business rules about crypto
internal/auth          OIDC (code+PKCE), roles, rate limiter
internal/api           guard + handlers (session, vault keys, items, spaces, devices, admin, extension sign-in)
internal/audit         audit log + sinks (SkyNet)
internal/skynet        outbox shipper, command verification, deny list
internal/keys          pepper and cookie key
internal/httpx         headers, client address, JSON helpers
internal/web           pages, embedded static files (CSS, JS, icons, logo), extension download
internal/app           wiring, housekeeping, deny middleware
internal/e2e           end-to-end tests with a fake ClosedDoor and a fake SkyNet
```

## Recipes

| Task | Do this |
|---|---|
| New endpoint | handler in `internal/api`, register in `Routes` with the right `need`, store method(s), e2e test, entry in `docs/api.md`; if it is security relevant, an audit event listed in `docs/security.md` |
| New item type | add it to `TYPES` in `core/item.js` (fields drive the editor, detail view, import, search); icon in `icons.svg`; a node test |
| New schema | append a migration in `store/migrations.go`; never edit an applied one |
| New setting | `config.Load`, `config_test.go`, `deploy/.env.sample`, `docker-compose.yml`, `docs/operations.md` |
| Change crypto | **do not edit v1.** Add `v2` next to it, keep v1 reading, document in `docs/crypto.md`, add vectors and tamper tests |
| New screen | `js/app/<name>.js`, route in `shell.js`, a step in `tests/ui/run.mjs` with axe and a screenshot |
| New icon | `<symbol id="i-name" viewBox="0 0 24 24">` (stroke style) in `static/icons.svg`, then `npm run sync` |
| Touch the core | edit `server/internal/web/static/js/core/`, run `npm run sync`, commit both |
| Release | tag on `main`; the Docker build packages the extension with the server so they always match |

## Gotchas

* The server has **no** way to check ciphertext. Validate shapes and sizes, enforce ownership and revisions, and leave the rest to the client's AAD binding.
* `?` placeholders only in SQL, and not in `LIMIT` (inline validated ints). All times are UTC unix seconds.
* `SameSite=Lax` on the session cookie is deliberate: a `Strict` cookie would not be sent on the redirect chain that starts at ClosedDoor.
* `form-action` is intentionally absent from the CSP (Chrome blocks the post-logout redirect to the SSO if it is set).
* The browser tests use `localhost` for the vault and `127.0.0.1` for the fake SSO and a test site: different host names, which is what makes the phishing tests meaningful.
