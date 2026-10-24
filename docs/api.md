# API reference

> This page documents the interface of the **web app and the Chrome extension** (cookie or extension session, vault data behind an unlock). Scripts and other systems use the separate, optional **[automation API](automation-api.md)**: ClosedDoor API keys, administration and operations only, no vault content. They share the `/api/v1/` prefix but never each other's credentials.

JSON over HTTPS, prefix `/api/v1`. Errors are `{"error": "<code>", "message": "<for people>"}`. All responses are `Cache-Control: no-store`.

**Authentication.** Web: the session cookie plus header `X-Vault-CSRF` (from `GET /session`) on every non-GET. Extension: `Authorization: Bearer vxs_…` (no CSRF header). Requests with a body need `Content-Type: application/json`; unknown fields are refused.

**Unlock.** Routes marked 🔓 additionally need an unlocked session (`423 locked` otherwise) and slide the unlock window.

Binary values are base64url without padding. An *envelope* is `1.<iv>.<ciphertext>` ([crypto.md](crypto.md)). Ids are 32 lowercase hex characters; `vault_id` is `personal` or a space id.

## Session

| Method | Path | |
|---|---|---|
| GET | `/session` | `{user, csrf, kind, vault:{state: none\|locked\|unlocked, unlocked_until}, sso:{fresh, expires_at}, idle_lock_minutes, version, can_plain_export, extension_ids}` |
| POST | `/session/logout` | ends the session; `{redirect}` is ClosedDoor's end-session URL (web) |
| PUT | `/settings` | `{idle_lock_minutes: 1..480}` |
| GET | `/sessions` | the person's browsers and extensions (`id`, `kind`, `label`, `ip`, `last_seen`, `unlocked`, `current`) |
| DELETE | `/sessions/{id}` | sign one out |
| POST | `/sessions/revoke-others` | sign out all but this one |
| GET | `/activity` | the person's own audit trail (newest 100) |
| POST 🔓 | `/audit/client` | `{event: vault_export\|vault_export_encrypted\|vault_import_file, count}` (advisory: exports happen in the browser) |

## Vault keys

| Method | Path | Body → result |
|---|---|---|
| GET | `/vault/prelogin` | `{kdf, iterations, salt, key_version}`; 404 `no_vault` |
| POST | `/vault/setup` | `{kdf, iterations, salt, auth, key_version:1, wrapped_uk, enc_pub, sig_pub, enc_priv, sig_priv, recovery:{proof, wrapped_uk}}`; once per person; leaves the session unlocked |
| POST | `/vault/unlock` | `{auth}` → `{wrapped_uk, key_version, enc_pub, sig_pub, enc_priv, sig_priv, kdf, iterations, salt, unlocked_until}`. `401 bad_password` (with `failed`, `retry_after` after the 5th), `429 locked_out`, `401 sso_expired` |
| POST | `/vault/lock` | |
| POST 🔓 | `/vault/ping` | keeps the unlock window open |
| POST 🔓 | `/vault/verify` | `{auth}` re-check before a dangerous action (same throttle as unlock) |
| POST 🔓 | `/vault/password` | `{auth_old, auth_new, kdf, iterations, salt, wrapped_uk}`; ends other sessions |
| POST | `/vault/recovery/start` | `{proof}` → `{wrapped_uk, enc_pub, sig_pub, enc_priv, sig_priv}` |
| POST | `/vault/recovery/finish` | `{proof, auth_new, kdf, iterations, salt, wrapped_uk, recovery:{proof, wrapped_uk}}`; ends other sessions |
| POST 🔓 | `/vault/recovery/rotate` | `{auth, recovery:{proof, wrapped_uk}}` |
| POST | `/vault/erase` | `{auth}` deletes the person's own vault |

## Items 🔓

| Method | Path | |
|---|---|---|
| GET | `/sync?since=N` | `{seq, more, key_version, items:[{id, vault_id, seq, blob, key_version, created_at, updated_at, deleted_at?, purged?}], spaces:[…]}`; repeat while `more`. `since=0` is a full download and is audited. |
| PUT | `/items/{id}` | `{vault_id, base_seq (0 = new), key_version, blob}` → item metadata. `409 conflict` carries `current`. Owner/editor only in spaces. |
| DELETE | `/items/{id}[?purge=1]` | trash, or remove the ciphertext for good (a tombstone remains) |
| POST | `/items/{id}/restore` | |
| GET | `/items/{id}/versions` | the last 10 encrypted versions |
| POST | `/items/import` | `{key_version, items:[{id, blob}]}` up to 500, personal vault, all-or-nothing |

A `space` in `/sync` is `{id, name_blob, key_version, needs_rotation, role, wrap:{eph, ct, sig, by}, wrap_key_version, wrap_by_sig_pub, members:[{sub, name, email, role, enc_pub, sig_pub}]}`.

## Spaces 🔓

| Method | Path | |
|---|---|---|
| GET | `/directory?q=` | people with a vault (≥ 2 letters, 10 results): `{sub, name, email, enc_pub, sig_pub}` |
| GET | `/users/{sub}/keys` | one person's public keys |
| POST | `/spaces` | `{id, name_blob, wrap:{eph, ct, sig}}` (the creator is the first owner) |
| PUT | `/spaces/{id}` | `{name_blob}` (owner) |
| DELETE | `/spaces/{id}` | owner; items become tombstones |
| POST | `/spaces/{id}/members` | `{sub, role, key_version, wrap}` (owner; refused while `needs_rotation`) |
| PUT | `/spaces/{id}/members/{sub}` | `{role}` (owner; the last owner cannot be demoted) |
| DELETE | `/spaces/{id}/members/{sub}` | owner removes anyone, anyone leaves; flags `needs_rotation` |
| POST | `/spaces/{id}/rotate` | `{key_version: current+1, name_blob, items:[{id, base_seq, blob}], members:[{sub, wrap}]}`: must cover exactly the live items and exactly the members |

## Extension sign-in

| Method | Path | |
|---|---|---|
| GET | `/ext/auth?redirect_uri&code_challenge&code_challenge_method=S256&state[&prompt=none]` | browser navigation; runs ClosedDoor sign-in and redirects to `https://<id>.chromiumapp.org/…?code=…&state=…` (or `?error=login_required\|access_denied\|…`). `redirect_uri` must be `https://<id>.chromiumapp.org/…` for an id in `VAULT_EXTENSION_IDS`; anything else gets an error page, never a redirect. |
| POST | `/api/v1/ext/token` | `{code, verifier, redirect_uri, label}` → `{token, expires_at, user}`. The code lives 60 s and is single use; PKCE is checked; an `Authorization: Bearer <old token>` header renews a session and keeps its unlock state. |

## Administration (role `admin`)

| Method | Path | |
|---|---|---|
| GET | `/admin/overview` | `{stats, users:[…counts…], skynet, version}` (no content) |
| GET | `/admin/audit?limit&actor` | audit rows |
| POST | `/admin/users/{sub}/lock` · `/unlock` · `/revoke-sessions` | |
| POST | `/admin/users/{sub}/erase-vault` | `{confirm: <their email>}` |

## Pages and static

`GET /login`, `GET /` (the app), `GET /static/*`, `GET /healthz`, `GET /download/extension.zip` and `GET /download/extension.json` (signed-in only; the package with the vault address added as `vault.json`, and its version, size and SHA-256), `GET /auth/login[?silent=1&return=/path]`, `GET /auth/callback`.
