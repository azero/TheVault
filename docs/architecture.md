# Architecture

```
 Staff browser ── HTTPS ─▶ reverse proxy ─▶ ┌────────────────────── TheVault (Go, one container) ──────────────────────┐
   web app (static JS)                       │ /login /auth/*  OIDC code+PKCE ◀──────────────▶ ClosedDoor (SSO)          │
   crypto core (WebCrypto)                   │ /api/v1/*       JSON: vault, items, spaces, sessions, admin               │
 Chrome extension ── HTTPS + Bearer ───────▶ │ /ext/auth       sign-in window for the extension (PKCE, one-time code)    │
   (service worker, popup, content script)   │ SQLite /data/vault.db  ciphertext + sessions + audit + outbox + deny list │
                                             │ audit ─▶ outbox ─▶ NDJSON/gzip ─▶ SkyNet /api/v1/ingest                   │
 SkyNet ── signed block_ip commands ───────▶ │ poller verifies Ed25519 ─▶ deny list ─▶ HTTP 403 for that address        │
                                             └───────────────────────────────────────────────────────────────────────────┘
```

## What runs where

| Part | Does | Never does |
|---|---|---|
| **Browser / extension** | all key derivation, encryption, decryption, TOTP, generator, search, import/export | send a secret or the master password to the server |
| **Server** | authenticates people (ClosedDoor), authorises access, stores ciphertext, throttles, audits, ships events, enforces blocks | decrypt anything, hold a key that could |
| **ClosedDoor** | says who the person is and whether they may use the app, and whether they are an admin | see the vault |
| **SkyNet** | collects events, raises alerts, signs block commands | read the vault; it only ever sees ids, counts and addresses |

## Data on disk (`VAULT_DATA_DIR`, default `/data`)

| Path | Contents |
|---|---|
| `vault.db` | users, `vault_keys` (sealed keys and proof hashes), `items` (ciphertext), `item_versions`, `spaces`, `space_members` (wraps), `sessions` (token hashes), `ext_codes`, `audit_log`, `outbox`, `deny_list`, `settings` |
| `keys/pepper.key` | HMAC pepper for proof hashes (generated on first start) |
| `keys/session.key` | HMAC key signing the pre-login cookie |
| `keys/skynet.json` | SkyNet credentials after enrolling (mode 0600) |
| `backups/` | `thevault backup` snapshots (`VACUUM INTO`, safe while running) |

Replace the container image and nothing is lost: migrations are append-only and a build refuses to open a database from a newer schema.

## A request

1. `Server.handle` (`internal/api/api.go`): bearer token (extension) or session cookie (web) → session lookup (hash at rest, idle and absolute timeouts) → SSO re-validation every five minutes while the token is valid → rate limit → admin lock → origin check → CSRF header (cookie sessions) → role → *unlocked* check for anything that touches vault data.
2. The handler validates the *shape* of what it received (ids, sizes, base64url, envelope format, enums) and calls `Store`, which enforces ownership, membership, role and revisions in one transaction.
3. Security-relevant outcomes go to `audit.Auditor`: a row in `audit_log` and, in parallel, a SkyNet event.

## Sync model

Every write bumps one global counter (`seq`). A client remembers the highest `seq` it saw and asks for `GET /sync?since=N`; deletes are tombstones (`purged`) so other devices learn about them. A write carries the `seq` the client last saw for that item (`base_seq`); a stale one gets `409` with the current copy. Spaces are always returned in full (names, role, wrap, members). Space rotation is one atomic request.

## Sessions and locking

Signing in (ClosedDoor) and **unlocking** (master password) are separate. A session starts locked; `POST /vault/unlock` verifies the proof and opens a sliding window (15 minutes by default, per-person 1 minute to 8 hours). Item endpoints refuse with `423` outside it. Unlocking needs a fresh ClosedDoor token; an already unlocked session may outlive its token by two hours (ClosedDoor has no refresh tokens, and a page navigation would throw away the in-memory keys), then it must unlock again. The extension renews its token silently and keeps its unlock state when it does.

## Not implemented (by design for v1)

Attachments, emergency access, per-item sharing outside spaces, Argon2id (the KDF parameters are versioned so it can be added), 2FA for the master password (ClosedDoor sign-in is the first factor; a second one belongs there), mobile apps and other browsers (the API and core are browser-neutral; Firefox needs a manifest port), breach lookups against external services (it would break "nothing leaves"; run it server-side if you want it).
