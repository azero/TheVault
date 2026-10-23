# AGENTS.md: TheVault

Instructions for AI coding agents (and humans) working in this repository. Read this first; deeper material is in [`docs/`](docs/README.md).

## What this is

TheVault is our company **password and secrets manager**: a web UI plus a Chrome extension for logins, API keys, server credentials, notes and cards, with shared team *spaces*. Staff sign in through **ClosedDoor SSO** (OIDC); security events go to **SkyNet**, and SkyNet's signed `block_ip` commands are enforced by the server.

It is **zero-knowledge**: the server stores only ciphertext. Everything is encrypted and decrypted in the browser/extension with keys derived from the user's master password (see [docs/crypto.md](docs/crypto.md)). Anything that would let the server (or someone with the database) read a secret is a **security bug**, not a design choice.

## Components

| Dir | What | Language |
|---|---|---|
| `server/` | API, storage, SSO login, SkyNet shipping/enforcement, embedded web UI | Go (version pinned in `server/go.mod`), one static binary |
| `server/internal/web/static/js/core/` | **The crypto core.** Used by the web UI *and* the extension. No DOM, no network. | JavaScript (ES modules, no dependencies) |
| `server/internal/web/static/js/app/` | The web UI (single-page, hash routing) | JavaScript |
| `extension/` | Chrome MV3 extension: popup, service worker, content script | JavaScript |
| `tests/js/` | Node tests for the core; `tests/ui/` Playwright browser tests | JavaScript |
| `deploy/` | Dockerfile, Portainer stack, env sample | |
| `docs/` | architecture, crypto, security, threat model, API, SkyNet, extension, operations | |

## Hard constraints (do not violate without asking the owner)

1. **The server never sees plaintext secrets or the master password, and never stores anything it could decrypt them with.** No server-side decryption code, no "admin can read" back door, no plaintext in logs, audit rows or SkyNet events. The server also does not learn item names, URLs, types or folders (they are inside the encrypted blob). New metadata the server can see needs a security-review note in docs/threat-model.md.
2. **Crypto only through WebCrypto** (`crypto.subtle`, `crypto.getRandomValues`), only inside `static/js/core/`. No hand-written ciphers/hashes, no third-party crypto library, no `Math.random()` for anything. Algorithms and parameters are fixed in docs/crypto.md; changing them means a new format version (`v2`), never an edit to `v1`.
3. **One self-contained container.** Static binary (`CGO_ENABLED=0`), pure-Go SQLite (`modernc.org/sqlite`), no sidecars. **All state lives under `VAULT_DATA_DIR` (`/data`)**: `vault.db`, `keys/`, `backups/`. The container root FS is read-only.
4. **Schema changes are append-only migrations** in `server/internal/store/migrations.go`. Never edit an applied migration. A build refuses to open a database from a newer schema.
5. **Secrets come from the environment, never committed.** `.env`, `data/`, `*.db`, `*.key`, `*.pem` are gitignored. Session ids, bearer tokens, auth proofs and recovery proofs are stored only as hashes/HMACs.
6. **Few dependencies.** Server deps: `go-oidc`, `x/oauth2`, `modernc.org/sqlite` (same as SkyNet). **No npm/CDN/third-party JavaScript in the product** (dev tooling in the root `package.json` is for tests only). Ask before adding anything.
7. **Web UI rules.** CSP: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'`. So: no inline `<script>`/`style`/`on*=`, no external assets, and **no `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval`** anywhere (Trusted Types makes them throw). Build DOM with `h()` from `js/app/dom.js`. `form-action` is intentionally absent (it breaks the post-logout redirect to the SSO).
8. **Extension rules.** Never autofill without an explicit user action. Fill only on an exact match of the saved URL rules (docs/extension.md), never into cross-origin frames or hidden fields, never over `http://` except localhost. The master password is only ever typed into the popup/options pages, never into a web page. Decrypted data is never written to `storage.local`; the unlock key lives only in `storage.session`.
9. **Every state-changing API call** goes through the guard: session or bearer token, role, unlocked vault (where the call needs it), CSRF header (cookie sessions), same-origin/extension-origin check.
10. **PHP/other runtimes are not used.** Go on the server, plain JS on the clients.
11. **The extension copy of the core is generated.** Edit `server/internal/web/static/js/core/`, then run `npm run sync` (copies into `extension/core/`); CI runs `npm run check:sync`.

## Commands

```bash
# server
cd server
gofmt -l .                      # must print nothing
go vet ./...
go test -race -count=1 ./...    # unit + end-to-end (fake SSO, fake SkyNet), no external services
go build -o thevault ./cmd/thevault

# run locally (needs an OIDC provider: a ClosedDoor app, or the fake one in tests/ui/devserver.mjs)
VAULT_DATA_DIR=./data VAULT_LISTEN=:8444 VAULT_PUBLIC_URL=http://localhost:8444 \
  VAULT_OIDC_ISSUER=... VAULT_OIDC_CLIENT_ID=... VAULT_OIDC_CLIENT_SECRET=... go run ./cmd/thevault serve

# JavaScript
npm install                     # dev tooling only (playwright-core, axe)
npm test                        # node:test: crypto core, TOTP, generator, URL matching, import/export
npm run check:sync              # extension/core == static/js/core
npm run build:extension         # dist/thevault-extension-<version>.zip
node tests/ui/run.mjs           # real server + fake SSO + headless Chromium: UI flows, CSP, axe, screenshots
node tests/ext/run.mjs          # loads the unpacked extension in Chromium: autofill and phishing cases
python3 tests/contrast.py       # WCAG AA check of the colour tokens, light + dark
```

## Conventions

- Go: standard layout `cmd/` + `internal/`. Errors wrapped with context; no panics on user input. Small packages. `?` placeholders only in SQL; `Store` is the only place SQL lives.
- **Everything from a client is untrusted.** Validate ids, sizes, base64url shape, enum values and envelope format (`v1.<iv>.<ct>`) before storing. The server cannot validate ciphertext, so it validates *shape and size* and enforces ownership/role/revision.
- Time: UTC; the database stores unix seconds.
- Security-relevant actions go to `Audit.Log(...)` (DB + SkyNet); list new event names in `docs/security.md` **and** map them in `internal/audit`.
- **Item blobs are bound to their id, vault and key version** through AES-GCM additional data. If you add a place that encrypts or decrypts, build the AAD with the helpers in `core/item.js`.
- JS: ES modules, 2 spaces, no semicolons-vs-semicolons wars (match the file), small pure functions in `core/`, DOM only in `app/`. UI strings are plain English; no frameworks.
- UI: style only through classes in `static/app.css` using its tokens; icons via `icon()` and `static/icons.svg`; one `<h1>` per view; every input has a label; new colour pairs go into `tests/contrast.py`.
- Add an end-to-end test (`server/internal/e2e`) for any API behaviour you add, a node test for any core function, and a UI test for any new screen.

## Security invariants: re-check on any change touching auth, keys, sharing, sync or extension

1. Sign-in: OIDC code + PKCE S256, `state`, `nonce`, RFC 9207 `iss`, RS256 only; pre-login state in an HMAC-signed cookie. ClosedDoor grants decide who may open the app; the `roles` claim only adds `admin`.
2. Sessions: opaque random id (hash at rest); cookie `__Host-` prefixed, `HttpOnly`, `Secure`, `SameSite=Lax` (the SSO callback is a cross-site navigation); idle 30 min / absolute 8 h for web, bearer sessions for the extension (hash at rest, revocable). Re-validated against `/userinfo` every 5 min while the SSO token is valid; an SSO *outage* keeps the session, a 401/403 ends it. **Unlock, extension re-auth and every admin route require a fresh SSO token** (an expired one cannot confirm that a role was not revoked).
3. A session must be **unlocked** (master-password proof verified server-side) to read or write vault data. Unlock failures are throttled per user (exponential lockout) and per IP, audited, and sent to SkyNet.
4. Auth proofs are HKDF outputs of the master key, stored as `HMAC-SHA256(pepper, proof)`; the pepper lives in `/data/keys/pepper.key`. Compared in constant time.
5. Item writes are optimistic-concurrency (`base_seq`); the server checks ownership/membership/role on every item, and a viewer can never write.
6. Space membership changes: removing a member requires a **key rotation** before the space is considered safe again (the UI forces it); wraps are ECDH-ephemeral + ECDSA-signed by the sharer, verified only with a key whose fingerprint was pinned (`resolveSharer`); never with a key the server merely names; public keys are derived from the unsealed private keys.
7. Changing the master password or using the recovery key ends all other sessions and extension devices.
8. Disabling a user in ClosedDoor, or locking them in the admin UI, ends access at the next check; admins can never read vault data.
9. CORS: only the exact `chrome-extension://<id>` origins in `VAULT_EXTENSION_IDS`, never `*`, never credentials. The web UI itself is same-origin only.
10. Nothing sensitive in URLs (no ids or secrets in query strings except one-time codes), no external resources, `Cache-Control: no-store` on every API/HTML response, no secrets in logs.
11. SkyNet commands are executed only if the Ed25519 signature (pinned key), agent id, expiry (<15 min window) and single-use id verify; never-block list (loopback, link-local, multicast, the SkyNet host, `VAULT_RESPONSE_ALLOWLIST`) is enforced here too.
12. Events sent to SkyNet never contain anything from a blob, a typed email that is not valid, or a secret.

Full threat model: [docs/threat-model.md](docs/threat-model.md), controls: [docs/security.md](docs/security.md).

## Branches

Develop on the designated branch (cloud sessions: `claude/<name>`); push often; never force-push `main`. Do not open a pull request unless the owner asks.

## Definition of done

- [ ] `gofmt`, `go vet`, `go test -race ./...` clean.
- [ ] `npm test`, `npm run check:sync` pass; `node tests/ui/run.mjs` passes **and you looked at the screenshots** (light, dark, phone).
- [ ] New behaviour has tests; docs in `docs/` updated; `deploy/.env.sample` updated for new settings.
- [ ] No secrets, keys, databases or logs staged.
