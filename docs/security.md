# Security controls

The invariants are in [AGENTS.md](../AGENTS.md). This page lists what is enforced, where, and which test proves it. The model of attackers is in [threat-model.md](threat-model.md).

## Sign-in and sessions

* **OIDC** authorization code + PKCE (S256), `state`, `nonce`, RFC 9207 `iss`, RS256 only; the pre-login state is in an HMAC-signed, 10-minute cookie (`SameSite=Lax`, because the callback is a cross-site navigation).
* **Who may enter** is decided by ClosedDoor's per-app grant. The `roles` claim only adds `admin`.
* **Session**: 256-bit random id, only its SHA-256 stored. Cookie `__Host-vault_session` (https): `HttpOnly`, `Secure`, `Path=/`, `SameSite=Lax`. Web sessions: idle 30 min, absolute 8 h. Extension sessions: bearer token (`vxs_…`, hash at rest), idle 14 days, absolute 30 days, revocable from *Settings → Devices*.
* **Re-validation**: every 5 minutes `/userinfo` is asked while the SSO token is valid; 401/403 ends the session at once, an outage keeps it. Unlocking always re-validates.
* **Locked accounts** (admin action): sessions deleted, sign-in refused, extension codes refused.
* **Session address changes** are audited (`session_ip_changed`).

## Unlock and recovery

* The master-password **proof** is verified server-side before any ciphertext is released. Proofs are stored peppered (HMAC); compared in constant time.
* Wrong proofs: four free, then lockout of 30 s doubling to 15 minutes, per person; per-IP limit of 20 attempts a minute; every failure and every lockout is audited and reaches SkyNet. `POST /vault/verify` (used before exports, new recovery keys, erasing) has the same throttle.
* **Recovery**: five wrong recovery proofs lock recovery for an hour. Recovery ends all other sessions and issues a new recovery key.
* Changing the master password ends all other sessions and extension devices.

## Requests

* Cookie sessions: `X-Vault-CSRF` header (per-session token), `Origin` must equal the public URL when present, `Sec-Fetch-Site` must be same-origin, JSON content type only, unknown JSON fields rejected, bodies size-capped.
* Bearer sessions: no ambient credential, so no CSRF; `Origin` must be absent, the public URL, or `chrome-extension://<id>` for an id in `VAULT_EXTENSION_IDS` (CORS answers only those, never `*`, never credentials).
* Cookie sessions are not accepted as bearer and vice versa.
* Server-side validation of shapes: ids `[0-9a-f]{32}`, envelopes `1.<iv>.<ct>`, public keys 65 bytes, KDF parameters within bounds, sizes (item 256 KB, import 500 per request).

## Browser

* CSP: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; require-trusted-types-for 'script'`.
* **Trusted Types** make `innerHTML`, `document.write`, `eval` and friends throw; the code builds DOM with `h()` only. The browser test asserts both the policy and that no inline script/style exists.
* Also: `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`, COOP/CORP `same-origin`, `Permissions-Policy`, HSTS over https, `Cache-Control: no-store` on every HTML and JSON response. No external resource is ever loaded (the browser test fails on one).
* Links built from data are limited to `http(s)`/`mailto`/same-site; external links open with `noopener noreferrer`.
* Clipboard is cleared after 30 s by default.

## Extension

See [extension.md](extension.md): explicit user action for every fill, exact-origin matching, top frame and frame must both match, visible fields only, https only (localhost excepted), master password only in extension pages, decrypted data never persisted, `isTrusted` checks on the save bar.

## SkyNet

* Events leave through a bounded on-disk outbox; nothing from an encrypted blob, no proof, no typed text other than a valid email, is ever in one (`internal/skynet/events.go`, asserted by an e2e test).
* Commands: Ed25519 signature over `skynet-cmd-v1\n‖payload` with the pinned public key, agent id, expiry, validity window ≤ 15 minutes, id recorded **before** acting (no replay across restarts), only `block_ip`/`unblock_ip`, dry-run honoured, never-block list (loopback, link-local, multicast, unspecified, broadcast, SkyNet itself, `VAULT_RESPONSE_ALLOWLIST`).

## Administrators

Administrators can: list people (counts, times), lock and unlock accounts, end sessions, erase a vault (typed confirmation), read the audit log, see SkyNet status. They **cannot** read, list or decrypt any item, and there is no route that could return one. Admin status is re-read from the session's SSO claims every five minutes, so demotion in ClosedDoor takes effect quickly.

## Audit events

Written to `audit_log` (365 days by default) and sent to SkyNet as `source: thevault`.

| Group | Events |
|---|---|
| Sign-in | `login`, `login_failed`, `login_denied`, `logout`, `session_revoked`, `role_changed`, `session_ip_changed`, `bearer_failed`, `ext_token_failed`, `ext_device_added` |
| Vault keys | `vault_created`, `unlock`, `unlock_failed`, `unlock_lockout`, `lock`, `master_password_changed`, `recovery_started`, `recovery_failed`, `recovery_used`, `recovery_rotated`, `vault_erased_self` |
| Data | `sync_full`, `item_created`, `item_updated`, `item_deleted`, `item_purged`, `item_restored`, `items_imported`, `vault_export`, `vault_export_encrypted`, `vault_import_file` |
| Spaces | `space_created`, `space_deleted`, `space_member_added`, `space_member_removed`, `space_member_role_changed`, `space_left`, `space_key_rotated` |
| Devices | `session_revoked_by_user`, `sessions_revoked_by_user` |
| Admin | `admin_user_locked`, `admin_user_unlocked`, `admin_sessions_revoked`, `admin_vault_erased` |
| Defence | `csrf_failed`, `origin_refused`, `blocked_request`; SkyNet only: `response_applied`, `heartbeat`, `events_dropped` |

Each person can read their own trail under *Settings → Activity*.

## Where it is tested

| Control | Test |
|---|---|
| Ciphertext binding, tampering, recovery, sharing | `tests/js/keys.test.mjs`, `items.test.mjs` |
| Phishing URL cases | `tests/js/urlmatch.test.mjs`, `tests/ext/run.mjs` |
| Throttling, lockout, SSO revocation and outage, CSRF/origin, sessions | `server/internal/e2e/api_test.go` |
| Space roles, rotation completeness | `server/internal/e2e/spaces_test.go` |
| Extension sign-in (PKCE, redirects, replay, renewal, CORS) | `server/internal/e2e/ext_test.go` |
| SkyNet events and commands | `server/internal/e2e/skynet_test.go` |
| CSP, Trusted Types, storage hygiene, accessibility | `tests/ui/run.mjs` |
