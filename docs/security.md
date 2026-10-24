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
* Wrong proofs: four free, then lockout of 30 s doubling to 15 minutes, per person; per-IP limit of 20 attempts a minute; every failure and every lockout is audited and reaches SkyNet. `POST /vault/verify` (used before exports, new recovery keys, erasing) and every other route that checks the master password has the same throttle, and checks are serialised per person so parallel guesses cannot race the lockout.
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

## Automation API

Optional (`VAULT_API_ENABLED`), described in [automation-api.md](automation-api.md); the reasoning is in [threat-model.md](threat-model.md#automation-api).

* **No vault content, no key material, in any form.** A key can never be unlocked, so nothing that needs an unlock is reachable, and nothing the server holds in readable form about a vault's content (not even ciphertext, item counts per person, or wrapped keys) is offered. A test seeds a vault and fetches every endpoint with every permission; none of it appears.
* **Credentials**: ClosedDoor API keys only (`cdk_` + 43 characters, at most 4096 bytes); anything else is refused without contacting ClosedDoor. Each request is verified live (`POST /api/introspect` with the sign-in's client); an unreachable ClosedDoor, or one that rejects TheVault's own credentials, answers 503 (fail closed). An optional cache (`VAULT_API_CACHE_SECONDS`, default 0, max 300, 30 advised) is the only delay in revocation.
* **Authority = permission AND role**: each route needs one permission (`audit:read`, `users:lock`, …) and, for a user key, the person's `admin` role label (exact match, read live) and an account that is not locked; service keys are bound by permission only. The last active administrator and (for user keys) the caller themselves cannot be locked.
* **Separate from the web UI**: no cookies, no CSRF token, no CORS (`OPTIONS` is 405). A session cookie or extension token never authenticates the API and an API key never authenticates the web UI.
* **Throttles**: per key (`VAULT_API_RATE_PER_MINUTE`, default 120, applied before ClosedDoor is asked) and 20 failed authentications per minute per client address (checked before ClosedDoor is asked again). 15 s request deadline, 1 MB JSON bodies, unknown fields rejected.
* **Audited**: failures, forbidden calls, rate limits, every mutating call and every sensitive read are recorded and sent to SkyNet with the key id and name; the key itself never is (at most 8 characters of a rejected key).

## OmniCore and notifications

Optional ([omnicore.md](omnicore.md)); the reasoning is in [threat-model.md](threat-model.md#omnicore-integration).

* **Signed only.** `/integrations/omnicore/v1/*` exists only when `VAULT_OMNICORE_KEYS` is set and answers nothing without a valid HMAC signature (key id, timestamp within ±120 s, single-use nonce, the person's `sub`, method and exact target are signed). Every failure is the same `401`. No cookies, no CSRF token, no CORS; a session cookie never authenticates it.
* **The key is a high-value secret**: it lets its holder read the widget data of every person (counts, times, device names, event names; never vault content). Environment only, never logged or rendered, rotate by listing two keys; secrets under 32 bytes are ignored.
* **No unlock, no content.** Widgets never read an unlock state, ciphertext, wrap, proof, key, token, space name or item data; the read models in `store/omnicore.go` select none of them. Per-person widgets are keyed by `sub`; administrator widgets are operational numbers; a locked account is refused.
* **Throttles**: 900 requests a minute per client address (429), `omnicore_auth_failed` audit rows thinned per address and in total.
* **Notifications** (Beacon) are produced from the audit trail by `internal/alerts`. Content rule: only what happened to the recipient's own account; never item, folder or space names, secrets, tokens, client-chosen device labels or other people's e-mail addresses. `unlock_failed` is limited to one message per person per 15 minutes. A Beacon outage never affects a request; the Beacon key is never logged.

## Administrators

Administrators can: list people (counts, times), lock and unlock accounts, end sessions, erase a vault (typed confirmation), read the audit log, see SkyNet status. (Through the optional automation API a key can do the same minus erasing a vault, and minus the per-person item and space counts.) They **cannot** read, list or decrypt any item, and there is no route that could return one. Admin status is re-read from ClosedDoor every five minutes while the access token is valid, and **every admin route requires a fresh token**: once it has expired the role cannot be confirmed, so the admin must lock and unlock (which signs in again) first. Erasing a vault keeps other members' spaces: each is flagged for rotation, one left without an owner promotes its longest-standing member, and the erased person's public keys are retained so the wraps they made stay verifiable until the rotation.

## Audit events

Written to `audit_log` (365 days by default) and sent to SkyNet as `source: thevault`.

| Group | Events |
|---|---|
| Sign-in | `login`, `login_failed`, `login_denied`, `logout`, `session_revoked`, `role_changed`, `session_ip_changed`, `bearer_failed`, `ext_token_failed`, `ext_device_added` |
| Vault keys | `vault_created`, `unlock`, `unlock_failed`, `unlock_lockout`, `lock`, `master_password_changed`, `recovery_started`, `recovery_failed`, `recovery_used`, `recovery_rotated`, `vault_erased_self` |
| Data | `sync_full`, `item_created`, `item_updated`, `item_deleted`, `item_purged`, `item_restored`, `items_imported`, `vault_export`, `vault_export_encrypted`, `vault_import_file` |
| Spaces | `space_created`, `space_deleted`, `space_member_added`, `space_member_removed`, `space_member_role_changed`, `space_left`, `space_key_rotated` |
| Devices | `session_revoked_by_user`, `sessions_revoked_by_user` |
| Admin | `admin_user_locked`, `admin_user_unlocked`, `admin_sessions_revoked`, `admin_vault_erased` (the first three are also written, with `via=api`, for actions taken through the automation API) |
| Automation API | `api_auth_failed` (`reason`: `malformed`, `invalid_token`, `unavailable`), `api_forbidden` (`reason`: `scope`, `role`), `api_rate_limited` (`by`: `key`, `ip`), `api_call` (every mutating call and every call to a sensitive read permission; `key_id`, `key_name`, `principal`, `scope`, `method`, `target`, `status`) |
| OmniCore | `omnicore_auth_failed` (a signed widget request was refused; `reason`: `method`, `body`, `unknown_key`, `timestamp`, `clock_skew`, `nonce`, `user`, `signature`, `replay`, `no_user`; `outcome=failure`; at most one row a minute per address and 30 a minute in total; SkyNet category `authentication`) |
| Defence | `csrf_failed`, `origin_refused`, `blocked_request`; SkyNet only: `response_applied`, `heartbeat`, `events_dropped` |

Each person can read their own trail under *Settings → Activity*: the events where they were the actor, plus what an administrator did to their account (`admin_*` events whose target is them; the administrator's address and browser are not shown). The target of every other event is an item, space or session id chosen by the caller, and ids have the same shape as a ClosedDoor `sub`, so it is never used to decide whose feed a row belongs to (`Store.ListUserAudit`); otherwise anyone could plant rows in a colleague's feed by naming an item after them. Administrators see the whole log and can filter it by account.

## Where it is tested

| Control | Test |
|---|---|
| Ciphertext binding, tampering, recovery, sharing | `tests/js/keys.test.mjs`, `items.test.mjs` |
| Phishing URL cases | `tests/js/urlmatch.test.mjs`, `tests/ext/run.mjs` |
| Throttling, lockout, SSO revocation and outage, CSRF/origin, sessions | `server/internal/e2e/api_test.go` |
| Space roles, rotation completeness | `server/internal/e2e/spaces_test.go` |
| Per-person isolation (activity feed, sessions, items and spaces after leaving, lookup throttle) | `server/internal/e2e/isolation_test.go` |
| Extension cache and unlock key do not carry over to another account | `tests/js/ext-account.test.mjs` |
| Extension sign-in (PKCE, redirects, replay, renewal, CORS) | `server/internal/e2e/ext_test.go` |
| SkyNet events and commands | `server/internal/e2e/skynet_test.go` |
| Automation API: authentication, scopes, roles, throttles, no CORS or cookies, no vault content, events without secrets | `server/internal/automation/automation_test.go`, `server/internal/e2e/apikeys_test.go` |
| OmniCore widgets and Beacon notifications: signing, isolation, roles, no content, floor, outage | `server/internal/omniconnect` (vendored vectors), `server/internal/e2e/omnicore_test.go` |
| CSP, Trusted Types, storage hygiene, accessibility | `tests/ui/run.mjs` |
