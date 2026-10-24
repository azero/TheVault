# AGENTS.md: TheVault

Instructions for AI coding agents (and humans) working in this repository. Read this first; deeper material is in [`docs/`](docs/README.md).

## What this is

TheVault is our company **password and secrets manager**: a web UI plus a Chrome extension for logins, API keys, server credentials, notes and cards, with shared team *spaces*. Staff sign in through **ClosedDoor SSO** (OIDC); security events go to **SkyNet**, and SkyNet's signed `block_ip` commands are enforced by the server.

It is **zero-knowledge**: the server stores only ciphertext. Everything is encrypted and decrypted in the browser/extension with keys derived from the user's master password (see [docs/crypto.md](docs/crypto.md)). Anything that would let the server (or someone with the database) read a secret is a **security bug**, not a design choice.

## Components

| Dir | What | Language |
|---|---|---|
| `server/` | API, storage, SSO login, SkyNet shipping/enforcement, embedded web UI, optional automation API for scripts | Go (version pinned in `server/go.mod`), one static binary |
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
6. **Few dependencies.** Server deps: `go-oidc`, `x/oauth2`, `modernc.org/sqlite` (same as SkyNet). `internal/closeddoorapi` is ClosedDoor's stdlib-only API-key verifier, vendored **unchanged** from `ClosedDoor/clients/go/closeddoorapi` (fix bugs upstream, then re-copy). **No npm/CDN/third-party JavaScript in the product** (dev tooling in the root `package.json` is for tests only). Ask before adding anything.
7. **Web UI rules.** CSP: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'`. So: no inline `<script>`/`style`/`on*=`, no external assets, and **no `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/`eval`** anywhere (Trusted Types makes them throw). Build DOM with `h()` from `js/app/dom.js`. `form-action` is intentionally absent (it breaks the post-logout redirect to the SSO).
8. **Extension rules.** Never autofill without an explicit user action. Fill only on an exact match of the saved URL rules (docs/extension.md), never into cross-origin frames or hidden fields, never over `http://` except localhost. The master password is only ever typed into the popup/options pages, never into a web page. Decrypted data is never written to `storage.local`; the unlock key lives only in `storage.session`.
9. **Every state-changing call of the browser/extension API** goes through the guard: session or bearer token, role, unlocked vault (where the call needs it), CSRF header (cookie sessions), same-origin/extension-origin check. The separate **automation API** (`internal/automation`) has its own guard (ClosedDoor API key, permission, role; see invariants 13 to 17) and is the only other way in.
10. **PHP/other runtimes are not used.** Go on the server, plain JS on the clients.
11. **The automation API exposes no vault content, ever** (`internal/automation`, [docs/automation-api.md](docs/automation-api.md)). An API key can never be unlocked, so no item, folder, space content, ciphertext, key material, wrapped or public key, KDF parameter or per-person item/space count may appear in any of its responses, events or errors, and no route may touch the unlock machinery. It stays an administration and operations interface (health, accounts, sessions, audit, SkyNet block list). Adding a route that returns anything derived from a vault needs the owner's explicit decision and a threat-model entry; a test fails if a route path suggests vault content.
12. **The extension copy of the core is generated.** Edit `server/internal/web/static/js/core/`, then run `npm run sync` (copies into `extension/core/`); CI runs `npm run check:sync`.

## Commands

```bash
# server
cd server
gofmt -l .                      # must print nothing
go vet ./...
go test -race -count=1 ./...    # unit + end-to-end (fake SSO, fake SkyNet), no external services
go build -o thevault ./cmd/thevault

go run ./cmd/thevault api-scopes   # the automation API's permissions, paste-ready for ClosedDoor (Admin > Applications > TheVault > API permissions)

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
- Security-relevant actions go to `Audit.Log(...)` (DB + SkyNet); list new event names in `docs/security.md` **and** give them a SkyNet category (`category()` in `internal/skynet/events.go`, or `audit.Event.Category` for a one-off; `audit.Event.User` overrides the person shown to SkyNet).
- **Adding an automation API endpoint**: 1) scope in `automation.Catalog` (`name:action`, description at most 190 chars, `Sensitive` for personal data or account changes, SkyNet category); 2) the route in `routes()` with exactly one scope and whether user keys need the `admin` role; 3) the handler in `internal/automation/handlers.go` (reuse the `store` function and the safety rules of the matching admin screen, validate every id and parameter, paginate lists, never return vault content); 4) `docs/automation-api.md`: endpoint section, permissions-table row, and the `thevault api-scopes` block (a test compares it byte for byte); 5) tests: a unit test and e2e success + failure + the scope matrix (`e2e/apikeys_test.go`), and the audit/SkyNet check.
- **Item blobs are bound to their id, vault and key version** through AES-GCM additional data. If you add a place that encrypts or decrypts, build the AAD with the helpers in `core/item.js`.
- JS: ES modules, 2 spaces, no semicolons-vs-semicolons wars (match the file), small pure functions in `core/`, DOM only in `app/`. UI strings are plain English; no frameworks.
- UI: style only through classes in `static/app.css` using its tokens; icons via `icon()` and `static/icons.svg`; one `<h1>` per view; every input has a label; new colour pairs go into `tests/contrast.py`.
- Add an end-to-end test (`server/internal/e2e`) for any API behaviour you add, a node test for any core function, and a UI test for any new screen.

## OmniCore integration

TheVault can show widgets in OmniCore (signed read-only endpoints, `internal/omnicore`) and send notifications through Beacon (`internal/alerts`). Details: [docs/omnicore.md](docs/omnicore.md). What a future agent must keep:

- **Signed only.** The endpoints exist only when `VAULT_OMNICORE_KEYS` is set, answer nothing without a valid signature, and every failure is the same `401`. They are GET-only and live outside the session/CSRF guard (they carry no cookie). The key is a high-value secret: never log or render it, 32 bytes minimum.
- **Zero-knowledge first.** A widget never needs, implies or grants an unlocked vault, and never selects ciphertext, wraps, proofs, keys, tokens, or anything inside a blob (item, folder, **space names**). Only counts, times, names the person gave their own devices and audit event names. A new widget field that is new server-visible metadata needs a security-review note in docs/threat-model.md. Per-person widgets are keyed by the `sub`; administrator widgets are operational numbers, never per-person data.
- **Own data only, TheVault's own roles.** Map the `sub` to the `users` table; never take OmniCore's word for roles. Unknown `sub` is `not_linked`, a locked account is `forbidden`.
- **Notifications carry no content**: only what happened to the recipient's own account (and anonymous operational events for the admin group); no item/folder/space names, secrets, tokens, client-chosen labels or other people's e-mail addresses. They are driven by the audit trail (`alerts.Sink`), never block a request, and `unlock_failed` stays rate limited. Mandatory categories are only security events about the recipient's own account.
- **Vendored libraries.** `internal/omniconnect` and `internal/notify` (and `omniconnect/testdata/testvectors.json`) are copied verbatim from OmniCore's `reference/go`; change them upstream, not here.
- New event name `omnicore_auth_failed` is listed in docs/security.md and mapped in `internal/skynet/events.go`.

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
13. Automation API credentials: only `cdk_` keys of the exact shape (never cookies, extension tokens or access tokens), verified live by ClosedDoor on every request (cache only if `VAULT_API_CACHE_SECONDS` > 0); an unreachable ClosedDoor, or one that rejects our own client credentials, is `503` and **fails closed**. Credentials are never logged, audited or sent to SkyNet (at most 8 characters of a rejected key-shaped value).
14. Automation API authority = permission AND role: every route needs one catalogued scope; user keys additionally need the exact `admin` role label (read live) and an account not locked in TheVault; service keys are bound by scope only. Keep the guards of the admin screen (no self-lock) and the last-active-administrator guard.
15. The automation API has no cookies, no CSRF token and no CORS (`OPTIONS` is 405); a cookie session never authenticates it and an API key never authenticates the web/extension API. Unknown paths and wrong methods get 404/405 without asking ClosedDoor; credentials not shaped like keys get 401 without asking ClosedDoor.
16. Failed authentication is throttled per client address (20 a minute, checked before ClosedDoor is asked), requests per key (`VAULT_API_RATE_PER_MINUTE`); 15 s request deadline; 1 MB JSON-only bodies with unknown fields rejected.
17. Automation API audit: `api_auth_failed`, `api_forbidden`, `api_rate_limited` and `api_call` (every mutating call and every sensitive read) with `key_id`, `key_name`, `principal`; the domain events (`admin_user_locked`, …) are written too, with `via=api`.

Full threat model: [docs/threat-model.md](docs/threat-model.md), controls: [docs/security.md](docs/security.md).

## Branches

Develop on the designated branch (cloud sessions: `claude/<name>`); push often; never force-push `main`. Do not open a pull request unless the owner asks.

## Definition of done

- [ ] `gofmt`, `go vet`, `go test -race ./...` clean.
- [ ] `npm test`, `npm run check:sync` pass; `node tests/ui/run.mjs` passes **and you looked at the screenshots** (light, dark, phone).
- [ ] New behaviour has tests; docs in `docs/` updated; `deploy/.env.sample` updated for new settings.
- [ ] Automation API changes: `Catalog`, routes and `docs/automation-api.md` agree (the catalog tests fail otherwise), and nothing returned is derived from vault content.
- [ ] No secrets, keys, databases or logs staged.
