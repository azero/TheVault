# Automation API

A small REST API for **scripts and other systems** that operate TheVault: monitoring, offboarding automation, incident response, audit export. Callers authenticate with a **ClosedDoor API key** (`cdk_…`), and every permission is granted per key in ClosedDoor. It is **off unless you enable it**.

This is a different interface from the one the web app and the browser extension use ([api.md](api.md)). Same path prefix (`/api/v1/`), different credential, different purpose: a cookie or an extension token never works here, and an API key never works there.

## What it deliberately cannot do

TheVault is zero-knowledge ([crypto.md](crypto.md)): the server stores only ciphertext, and a session must be *unlocked* with a proof of the master password before it may read or write any vault data. **An API key has no master password and can never be unlocked.** So this API exposes **no vault content in any form**, and that is a design rule, not a missing feature:

* no item, folder, tag, note, space name or space content, not even as ciphertext (so no "export" or "backup download" either);
* no key material: no salt or KDF parameters, wrapped keys, public keys, auth proofs, recovery data;
* no per-person item or space counts (the administration screen shows them; automation has no use for them, so they are left out);
* it cannot unlock a vault, check or reset a master password, or start a recovery;
* it cannot **erase a vault** (irreversible; stays a typed-confirmation action in the administration screen);
* it cannot create or delete accounts or change roles (that is ClosedDoor's job), and it cannot add or remove SkyNet blocks (read-only view);
* it cannot create or restore backups (`thevault backup` is a command on the host; the API only lists snapshot names, sizes and times).

What is left is **administration and operations**: health, accounts, sessions, the audit log, SkyNet's block list. Everything it returns is metadata the administration screens already show an administrator; nothing there is vault content, and the reasoning is in [threat-model.md](threat-model.md#automation-api). Compromise of an API key therefore cannot disclose a secret. It can disrupt (lock accounts, end sessions) and it can disclose personal data and the audit trail, which is why those permissions are separate and audited.

## Turn it on

| Variable | Default | |
|---|---|---|
| `VAULT_API_ENABLED` | off | `true` registers the routes. While off they do not exist (the router answers 404, or 405 where the browser API's CORS preflight pattern claims the prefix) and TheVault never contacts ClosedDoor for keys |
| `VAULT_API_CACHE_SECONDS` | `0` | how long an answer from ClosedDoor may be reused. `0` asks ClosedDoor on every request, so a revoked key stops at once. A cache means a revoked key keeps working for up to that long; **30 or less is advised**, the server logs a warning above that, and 300 is the maximum |
| `VAULT_API_RATE_PER_MINUTE` | `120` | requests per key per minute (1 to 100000) |

Keys are verified by ClosedDoor with the **same confidential client** TheVault already uses to sign people in (`VAULT_OIDC_ISSUER`, `VAULT_OIDC_CLIENT_ID`, `VAULT_OIDC_CLIENT_SECRET`); there is nothing else to configure. The server refuses to start if the API is enabled without them. Behind a reverse proxy, set `VAULT_TRUSTED_IP_HEADER` too: the per-address throttle and the audit trail use the same client address as the rest of the app.

## Register the permissions in ClosedDoor and create a key

1. In ClosedDoor: *Admin → Applications → TheVault → API permissions*. Paste this block (it is the output of `thevault api-scopes`, one `name  description` per line):

```
status:read  Read health, version, schema version, database size, SkyNet connection status and the list of backup snapshots (names, sizes, times). No vault data.
users:read  List and read accounts: id, name, email, role, locked state, whether a vault exists, sign-in times, number of sessions. Personal data.
users:lock  Lock an account like an administrator can: ends its sessions and refuses sign-in. Cannot lock yourself or the last administrator.
users:unlock  Unlock an account that was locked by an administrator.
sessions:read  List a person's browser and extension sessions: kind, label, address, times, whether unlocked. Metadata only, never tokens.
sessions:revoke  End one or all sessions of a person (web and extension devices). Signs them out; their vault is untouched.
audit:read  Read the audit log (events, actors, addresses, details), the same data the administration screen shows. Sensitive.
response:read  Read the addresses SkyNet has made TheVault block, with expiry and reason. Read-only.
```

2. *Admin → API keys → New key*. Choose a **service key** (a script; bound by the permissions you tick) or a **user key** (acts as one person; see below), tick TheVault and the permissions it needs, set an expiry, and copy the key. It is shown once.
3. Give the key to the script. Lost or leaked: *Generate new secret* or *Revoke* in ClosedDoor; it stops working here on the next request (or when the cache expires).

## Authentication

Send the key as `Authorization: Bearer cdk_…` or `X-API-Key: cdk_…`. The key must look like a key (`cdk_` and 43 URL-safe characters, at most 4096 bytes in the header); anything else, including ClosedDoor access tokens and TheVault extension tokens, is refused with 401 **without** asking ClosedDoor. Every request is verified live by ClosedDoor (revoked, expired, person disabled, access to TheVault removed, permission removed); this is the equivalent of the "fresh SSO sign-in" the administration screens require.

**Service keys** are bound by the permissions granted to the key and nothing else. **User keys** act as a person, and a user key can never do more than that person could in the web app: *effective authority = permission AND role*. Here every route except `/whoami` is an administration action, so a user key needs the person to hold the ClosedDoor role label **`admin`** for TheVault (exact match, read live on each request; "Admin", "administrator" or no label does not count) and not to be locked in TheVault. A person who is not an administrator gets `403 forbidden` even if someone ticked the permission for their key.

### Errors

Errors are JSON, `{"error": "<code>", "message": "<for people>"}`; every response is `Cache-Control: no-store` with `X-Content-Type-Options: nosniff`, and none sets a cookie. Paths and methods that do not exist are answered by the router (404 or 405) without any check.

| HTTP | `error` | Meaning |
|---|---|---|
| 400 | `invalid_request` | bad parameter, bad id, a body where none is allowed, wrong content type, unknown field, body over 1 MB |
| 401 | `invalid_token` | no key, not shaped like a key, or ClosedDoor says it is not valid here (`WWW-Authenticate: Bearer error="invalid_token"`) |
| 403 | `insufficient_scope` | the key lacks the permission; the body has `needs` (`WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`) |
| 403 | `forbidden` | a user key whose person may not do this in the web app (role, or locked) |
| 404 | `not_found` | no such person or session |
| 409 | `conflict` | would lock yourself or the last active administrator |
| 429 | `rate_limited` | per-key limit, or too many failed authentications from this address; `Retry-After` seconds |
| 500 | `server_error` | something failed on the server (details are only in its log) |
| 503 | `authentication_unavailable` | ClosedDoor cannot be reached or rejected TheVault's own credentials. The API **fails closed**: it never allows a request it could not verify |

## Permissions

| Permission | What it allows | Endpoints | Needs role (user keys) | Risk |
|---|---|---|---|---|
| *(none)* | see which key you are | `GET /api/v1/whoami` | none | none |
| `status:read` | health, version, schema, database size, SkyNet connection state, backup snapshot names and sizes | `GET /api/v1/status` | `admin` | low |
| `users:read` | list and read accounts (name, email, role, state, sign-in times) | `GET /api/v1/users`, `GET /api/v1/users/{sub}` | `admin` | medium: personal data |
| `users:lock` | lock an account: sign-in refused, all sessions ended | `POST /api/v1/users/{sub}/lock` | `admin` | high: denies a person access |
| `users:unlock` | unlock an account an administrator locked | `POST /api/v1/users/{sub}/unlock` | `admin` | high: re-admits an account that may have been locked for a reason |
| `sessions:read` | list a person's browsers and extension devices | `GET /api/v1/users/{sub}/sessions` | `admin` | medium: addresses and device labels |
| `sessions:revoke` | sign out one device or all of a person | `DELETE /api/v1/users/{sub}/sessions`, `DELETE /api/v1/users/{sub}/sessions/{id}` | `admin` | medium: disruptive, reversible by signing in again |
| `audit:read` | read the audit log | `GET /api/v1/audit` | `admin` | high: personal data and the security trail |
| `response:read` | read the addresses SkyNet made TheVault block | `GET /api/v1/response/blocks` | `admin` | low |

Reads and writes are separate, destructive actions have their own permission, and anything with personal data is separate from health checks. Give each integration only what it uses (a monitoring job needs `status:read` and nothing else).

## Endpoints

Times are unix seconds (UTC). `sub` is ClosedDoor's id for a person (letters, digits and `._:-`, up to 128). Examples below are output from a test server (ids and the version string replaced by realistic values).

### GET /api/v1/whoami

Any valid key, no permission needed. Returns who the key is and what it may do here.

```json
{
  "sub": "svc_nightly-report", "principal": "service", "key_id": "key_nightly-report", "key_name": "nightly-report",
  "scopes": ["status:read", "users:read", "users:lock", "users:unlock", "sessions:read", "sessions:revoke", "audit:read", "response:read"],
  "roles": []
}
```

For a user key, `principal` is `user`, `sub` is the person's id, `roles` their ClosedDoor labels for TheVault, and `name` and `email` are present.

### GET /api/v1/status

Permission `status:read`.

```json
{
  "status": "ok", "problems": [], "version": "1.4.0", "time": 1792780261, "uptime_seconds": 28,
  "schema": {"current": 2, "latest": 2},
  "database": {"bytes": 416128},
  "counts": {"users": 3, "vaults": 1, "sessions": 4, "audit_rows": 5},
  "skynet": {"enabled": true, "last_send": 1792780233, "last_error": "", "sent": 6, "outbox": 0, "dropped": 0, "commands_enabled": true, "last_command": 0, "command_error": ""},
  "backups": {"total": 1, "latest": [{"name": "vault-20261023-183033.db", "bytes": 155648, "modified": 1792780233}]}
}
```

`status` is `degraded` (with `problems` such as `skynet_events_failing`) when SkyNet is configured but not accepting events or commands. `counts` are server-wide totals; there are deliberately no item or space counts. `skynet` is `{"enabled": false}` when SkyNet is not configured, and never contains the agent id, the URL or the block list. `backups` lists at most the 20 newest snapshot files' names, sizes and times, never paths or contents.

### GET /api/v1/users

Permission `users:read`. Parameters: `limit` (1 to 200, default 50; larger values count as 200), `cursor` (the `next_cursor` of the previous page), `locked=true|false`. Ordered by `sub`; `next_cursor` is `null` on the last page.

```json
{
  "users": [
    {"sub": "7c1d9e0b4a2f4e58a6b3d0c9e1f25a47", "email": "ana@example.com", "name": "ana", "role": "member",
     "locked": false, "locked_out": false, "has_vault": true, "sessions": 2,
     "first_seen": 1792780233, "last_login": 1792780233, "last_unlock": 0}
  ],
  "next_cursor": null
}
```

`role` is the role as of the person's last sign-in. `locked` is the administrator lock; `locked_out` is the temporary lockout after wrong master-password attempts. `sessions` counts live web sessions and extension devices. Errors: `400 invalid_request` for a bad parameter.

### GET /api/v1/users/{sub}

Permission `users:read`. One account, same fields as above. `404 not_found` if the person has never signed in to TheVault.

### POST /api/v1/users/{sub}/lock

Permission `users:lock`. The administration screen's *Lock*: the account is refused at sign-in and every session of the person ends. Their data is untouched. No body (or `{}`).

```json
{"ok": true, "locked": true, "sessions_ended": 2}
```

Refused with `409 conflict` when the target is the person behind a user key (the screen refuses that too), and when the target is the **last active administrator** (a script has no "myself", so the API adds this guard; "administrator" here is the role recorded at each person's last sign-in). `404 not_found` for an unknown person. Locking an already locked account succeeds with `sessions_ended: 0`. The person's own activity trail shows *Account locked by an administrator*.

### POST /api/v1/users/{sub}/unlock

Permission `users:unlock`. The administration screen's *Unlock*. No body (or `{}`).

```json
{"ok": true, "locked": false}
```

It does not clear a master-password lockout (`locked_out`); that expires by itself.

### GET /api/v1/users/{sub}/sessions

Permission `sessions:read`. Parameters: `limit` (default 50, max 200), `offset` (default 0). Newest activity first.

```json
{
  "sessions": [
    {"id": "1af49e26841892b5", "kind": "web", "label": "Browser", "ip": "127.0.0.1",
     "created_at": 1792780233, "last_seen": 1792780233, "expires_at": 1792809033, "unlocked": true}
  ],
  "total": 2, "next_offset": 1
}
```

`kind` is `web` or `ext` (extension device). `id` is the 16-character public handle also used by *Settings → Devices*; it is not a credential. Tokens, CSRF tokens, SSO tokens and user-agent strings are never returned. `unlocked` says whether that session currently holds an unlocked vault. `404 not_found` for an unknown person.

### DELETE /api/v1/users/{sub}/sessions

Permission `sessions:revoke`. The administration screen's *End sessions*: every web session and extension device of the person. No body (or `{}`).

```json
{"revoked": 2}
```

### DELETE /api/v1/users/{sub}/sessions/{id}

Permission `sessions:revoke`. Ends one session, by the `id` from the list. `{"revoked": 1}`; `400 invalid_request` if `id` is not a 16-character hex id; `404 not_found` if that person has no such session (an id belonging to someone else is also `404`).

### GET /api/v1/audit

Permission `audit:read`. The same rows the administration screen shows, newest first. Parameters: `limit` (default 50, max 200), `cursor` (the `next_cursor` of the previous page), `actor` (a `sub`; matches rows where the person is the actor **or** the target, as the screen does), `event` (an event name from [security.md](security.md#audit-events)), `since` (unix seconds).

```json
{
  "events": [
    {"id": 10, "created_at": 1792780270, "event": "admin_user_locked", "actor": "svc_nightly-report",
     "target": "7c1d9e0b4a2f4e58a6b3d0c9e1f25a47", "ip": "127.0.0.1", "user_agent": "curl/8.5.0", "outcome": "success",
     "details": "key_id=key_nightly-report key_name=nightly-report principal=service sessions_ended=2 via=api"}
  ],
  "next_cursor": null
}
```

`next_cursor` is the smallest `id` of the page, or `null` at the end. Ids of items and spaces in `target` (and `vault=space:<id>` in `details`) are shortened to 12 characters, exactly as the administration screen shows them. Actions taken through this API appear twice: the ordinary event the person sees (`admin_user_locked`, …, with `via=api`) and an `api_call` row. Reading the audit log is itself recorded.

### GET /api/v1/response/blocks

Permission `response:read`. The addresses that SkyNet's signed `block_ip` commands made TheVault refuse, newest expiry first. Parameters: `limit`, `offset`. Read-only: blocks can only come from SkyNet.

```json
{
  "enforced": true, "commands_enabled": true,
  "blocks": [{"ip": "198.51.100.77", "until": 1792783833, "reason": "vault unlock brute force"}],
  "total": 1, "next_offset": null
}
```

`enforced` is false when SkyNet is not configured; `commands_enabled` is false when no command key is pinned (see [skynet.md](skynet.md)).

## Pagination

List endpoints never return unbounded data. `limit` defaults to 50 and is capped at 200. Users and the audit log use a **cursor** (`next_cursor`, pass it back as `cursor`; stable while rows are added); sessions and blocks are short lists and use `offset` (`next_offset`, `null` at the end).

## Limits and abuse protection

* **Per key**: `VAULT_API_RATE_PER_MINUTE` (default 120) per minute per key, sliding window, in memory; beyond it `429 rate_limited` with `Retry-After`. The limit is applied before ClosedDoor is asked, so a flood cannot be used to hammer it, and one key cannot use up another's allowance.
* **Per address**: 20 *failed* authentications (malformed or rejected keys) per minute per client address; after that every request from the address gets `429` **without contacting ClosedDoor** until the window clears. A ClosedDoor outage does not count as a failure.
* **Request time**: 15 seconds per request, 5 seconds for each question to ClosedDoor. Bodies: at most 1 MB, `application/json` only, unknown fields rejected. The action endpoints take no parameters, so a body is optional and, if sent, must be `{}`.
* **No cookies, no CSRF token, no CORS**: it is for servers. `OPTIONS` answers 405 and no `Access-Control-*` header is ever sent, so a browser page cannot read its responses. An address that SkyNet has made TheVault block is refused here too (the block applies to the whole server).

## What reaches the audit log and SkyNet

Events use TheVault's usual audit pipeline (a row in `audit_log`, and `source: thevault` to SkyNet; see [skynet.md](skynet.md)). The credential itself is never recorded: at most the first 8 characters (`cdk_` and four more) of a key that looked like a key and was rejected. The event's `user` is the person's email (else their `sub`) for a user key and `key:<key name>` for a service key.

| Event | SkyNet category | Outcome | When | Extra fields |
|---|---|---|---|---|
| `api_auth_failed` | `authentication` | failure | a credential was presented and rejected, or ClosedDoor was unavailable | `reason` = `malformed`, `invalid_token` or `unavailable`; `key_prefix` (only for a rejected key-shaped value) |
| `api_forbidden` | `authorization` | failure | a valid key without the permission (`reason=scope`) or whose person lacks the role or is locked (`reason=role`) | `key_id`, `key_name`, `principal`, `needs`, `reason` |
| `api_rate_limited` | `web` | failure | the per-key or per-address limit was hit (at most one event per minute per key or address) | `limit`, `by` (`key` or `ip`), `key_id` when known |
| `api_call` | `iam` for accounts and sessions, `system` for the audit log and block list | success or failure | **every** `POST`/`DELETE` and every call to `users:read`, `sessions:read`, `audit:read` and `response:read` | `key_id`, `key_name`, `principal`, `scope`, `method`, `target` (the request path), `status` |

`whoami` and `status:read` are not recorded individually (a monitor polling `status` would otherwise fill the log). Detecting "many failures" is SkyNet's job. Request bodies, query strings and responses are never recorded. The ordinary events `admin_user_locked`, `admin_user_unlocked` and `admin_sessions_revoked` are written for actions taken through the API with `via=api` and the key's id and name added.

## Operating it

* **One service key per integration**, with only the permissions it needs, and a short expiry that you rotate. Never share a key between systems: the audit trail names the key.
* Prefer **service keys** for automation. A **user key** carries a person's authority and is only as safe as that person's laptop; it stops when they lose the `admin` label, are locked, or are disabled in ClosedDoor.
* Keep `VAULT_API_CACHE_SECONDS` at 0, or at 30 at most; remember that revocation then takes up to that long.
* Alert on `api_auth_failed`, `api_forbidden` and `api_rate_limited` in SkyNet; review `api_call` for `users:lock`, `users:unlock` and `sessions:revoke`.
* Keys are stored by ClosedDoor only as hashes, and never by TheVault. Do not put them in URLs or logs; send them in a header.
* Set `VAULT_TRUSTED_IP_HEADER` behind a proxy, otherwise all callers share the proxy's address and the failure throttle applies to them together.

## Worked session

```bash
VAULT=https://vault.example.com
KEY=cdk_...        # a service key with the permissions you need

# who am I?
curl -s -H "Authorization: Bearer $KEY" $VAULT/api/v1/whoami

# health for a monitor
curl -s -H "X-API-Key: $KEY" $VAULT/api/v1/status

# page through accounts, 2 at a time
curl -s -H "Authorization: Bearer $KEY" "$VAULT/api/v1/users?limit=2"
curl -s -H "Authorization: Bearer $KEY" "$VAULT/api/v1/users?limit=2&cursor=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# incident: lock a person, end their devices, look at what happened
SUB=7c1d9e0b4a2f4e58a6b3d0c9e1f25a47
curl -s -X POST   -H "Authorization: Bearer $KEY" $VAULT/api/v1/users/$SUB/lock        # {"locked":true,"ok":true,"sessions_ended":2}
curl -s -H "Authorization: Bearer $KEY" "$VAULT/api/v1/audit?actor=$SUB&limit=20"
curl -s -X POST   -H "Authorization: Bearer $KEY" $VAULT/api/v1/users/$SUB/unlock      # {"locked":false,"ok":true}

# a key without the permission
curl -si -H "Authorization: Bearer $SMALL_KEY" $VAULT/api/v1/users
# HTTP/1.1 403 Forbidden
# Www-Authenticate: Bearer error="insufficient_scope", scope="users:read"
# {"error":"insufficient_scope","message":"This API key lacks the permission users:read.","needs":"users:read"}

# a key that is wrong, expired or revoked
curl -si -H "Authorization: Bearer cdk_0000000000000000000000000000000000000000000" $VAULT/api/v1/whoami
# HTTP/1.1 401 Unauthorized
# Www-Authenticate: Bearer error="invalid_token"
# {"error":"invalid_token","message":"The API key is invalid, expired or revoked."}
```

## How it is tested

`server/internal/automation` (unit tests with a stub ClosedDoor that counts questions: malformed and missing credentials, unavailable ClosedDoor, scope and role checks, rate limits, the per-address throttle, no introspection for unknown routes, no cookies, no CORS, body limits, pagination parameters, and the catalog tests that keep `Catalog`, the routes and this page in step) and `server/internal/e2e/apikeys_test.go` (the real handler against a fake ClosedDoor that implements `POST /api/introspect` and a fake SkyNet: every endpoint, a permission-per-endpoint matrix, revocation, the cache, user keys versus service keys, the last-administrator guard, SkyNet and audit events without secrets, and a test that seeds a vault and proves nothing of it is reachable). See [testing.md](testing.md).
