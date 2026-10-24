# OmniCore integration

OmniCore is the company dashboard (web and Android). TheVault takes part in two ways, both optional and both off until configured:

1. **Widgets**: a signed, read-only HTTP interface under `/integrations/omnicore/v1/` that OmniCore calls on behalf of a signed-in person.
2. **Notifications**: security events about a person's own account (and a few for administrators) are sent to **Beacon**, tagged with a category and a level so each person decides in OmniCore how much they hear.

Neither changes what TheVault is: **the server still never sees a secret.** A signed OmniCore request does not need, imply or grant an unlocked vault, and nothing here reads ciphertext, wrapped keys, proofs, salts, tokens, item names, folder names or space names (they are inside encrypted blobs; the server cannot show them). The protocol is OmniCore's `docs/integration.md` and `docs/notifications.md`; the code is vendored (see below).

## What is exposed

Everything below is metadata the server legitimately has and the person's own screens already show (counts, times, device names the person chose, event names). No new kind of metadata is stored or exposed; the only schema change is an index on the audit log (migration 4).

| Widget id | Kind | Who | What it shows |
|---|---|---|---|
| `vault_status` | status | everyone | vault created (date), recovery key configured, last unlock, wrong-password counter or an active lockout, number of extension devices signed in |
| `vault_size` | stat | everyone | number of items in the personal vault and in its trash (counts only) |
| `spaces` | stat | everyone | number of shared spaces the person belongs to, how many they own, how many of those need a key rotation (counts only; no names, they are encrypted) |
| `my_devices` | list | everyone | the person's live sessions: web sessions and extension devices, label (as the person set it or the default), when signed in, last seen. No address, no user agent, no token. Setting `show`: all or extensions only |
| `security_events` | list | everyone | the person's own recent events: wrong master password, lockout, wrong recovery key, recovery used, master password changed, extension device authorised or renewed, sessions signed out. Event type and time only. Setting `days`: 7, 30 or 90 |
| `unlock_failures` | series | everyone | wrong master passwords on the person's vault per day (setting `days`: 7, 14 or 30) |
| `users` | stat | administrators | active and locked accounts, administrators, vaults, accounts in an unlock lockout (counts only) |
| `failed_unlocks` | series | administrators | wrong master passwords across all accounts per hour (setting `hours`: 24, 72, 168). No names, no addresses |
| `blocked_ips` | list | administrators | addresses SkyNet currently has TheVault block, with expiry (the same list as *Administration, SkyNet*) |
| `sessions` | stat | administrators | live web sessions and extension devices, all accounts (counts only) |

The overview layout in OmniCore shows the first six (the ones for everyone). Not exposed on purpose: anything per person for administrators (an administrator cannot read vault data, and OmniCore does not change that), the audit trail of others, item and space contents or names, e-mail addresses, IP addresses of people, search (there is nothing the server could search without reading names).

There is no "pending invitations" widget: adding a person to a space is immediate in TheVault (they are told by notification, below), so there is nothing pending to count.

### Who is who

OmniCore sends only the ClosedDoor `sub`. TheVault maps it to its own account in the `users` table (a person who has never signed in to TheVault is `403 not_linked`; OmniCore tells them to open TheVault once) and applies **its own rules**, never OmniCore's words:

* An account **locked by an administrator** has no access to TheVault, so its widgets answer `403 forbidden`.
* **Administrator** widgets need the role `admin` as recorded at the person's last sign-in (the `roles` claim), and are refused if any of the person's live sessions has already been re-validated down to a lower role. A signed OmniCore request carries no ClosedDoor token, so, unlike TheVault's own admin routes, the role cannot be re-confirmed live; see the residual risk in [threat-model.md](threat-model.md#omnicore-integration).
* Every widget returns only the signed-in person's own rows (queries are keyed by `sub`). Administrator widgets return operational numbers only.

## Notifications

Sent through Beacon with `source: thevault`. Declared once at start (the catalog is `PUT` to Beacon and retried until accepted); people choose their threshold per application and category in OmniCore or Beacon. "Mandatory" categories are security events about the recipient's own account and cannot be switched off.

| Category | Level | Mandatory | Sent when | To |
|---|---|---|---|---|
| `new_device` | critical | yes | a browser extension was authorised for the account (not on a silent renewal of the same device) | that person |
| `master_password_changed` | critical | yes | the master password was changed | that person |
| `recovery_key_used` | critical | yes | the recovery key reset the master password | that person |
| `unlock_failed` | important | yes | from the third wrong master password since the last successful unlock; **at most one message per person per 15 minutes**, so an attacker cannot use TheVault to spam someone | that person |
| `space_invitation` | notice | no | someone added the person to a shared space; **at most two messages per sender and five in all per person per hour** (the addition itself always happens and shows in the app) | the person added |
| `member_removed_rotate` | important | no | a member was removed from, or left, a space the person owns; the key must be rotated | the space's owners |
| `admin_security` | important | no | SkyNet's signed `block_ip` was applied, an administrator locked an account, or erased a vault | the Beacon group `VAULT_NOTIFY_ADMIN_GROUP` (default `admins`) |

**Content rule.** Titles and bodies say what happened to the recipient's own account, and may contain the address the action came from (the person's own *Settings, Activity* shows it) and counts. They never contain item, folder or space names (unknown to the server), a device label chosen by a client, an e-mail address, a token, a proof or a key. The link opens TheVault itself, never an item or space. Administrator messages do not name the person who was locked or erased.

Notifications hang off the audit trail (`internal/alerts`, an audit sink), so each is tied to an audit row that already exists, a handler never waits for Beacon, and a Beacon outage is invisible to users: events are queued, retried a few times in memory and dropped; they are never written to the database. The app's own audit rows and SkyNet events are unchanged (one detail was added to `ext_device_added`: `replaced=true|false`, whether the extension replaced its own earlier token).

## Setting it up

1. **OmniCore**: *Settings, Applications, Add*: id `thevault`, base URL `https://vault.example.com` (your `VAULT_PUBLIC_URL`). OmniCore generates a key id (`ocr_…`) and a secret (`ocs_…`, shown once).
2. **TheVault**: set `VAULT_OMNICORE_KEYS=ocr_ab12cd34:ocs_…` and restart. To rotate, list both (`new,old`), change the key in OmniCore, then remove the old one. Secrets shorter than 32 bytes are ignored with a warning in the log. Without this setting the endpoints do not exist.
3. **Beacon** (for notifications): *Settings, API apps, Create*: scope `send`, allowed source `thevault`. Set `VAULT_BEACON_URL` and `VAULT_BEACON_KEY` (`<id>.<secret>`). Create a Beacon group for administrators (default name `admins`, or set `VAULT_NOTIFY_ADMIN_GROUP`). Optionally set `VAULT_NOTIFY_MIN_LEVEL` (`info` by default) to drop events below a level; mandatory categories always pass.

| Setting | Default | Meaning |
|---|---|---|
| `VAULT_OMNICORE_KEYS` | empty | `id:secret[,id2:secret2]`; at least 32 bytes per secret. A high-value secret: it lets OmniCore read every person's widgets |
| `VAULT_BEACON_URL` | empty | Beacon base URL (https; plain http only for localhost). Set together with the key, or both empty |
| `VAULT_BEACON_KEY` | empty | Beacon API key with scope `send`. Never logged |
| `VAULT_NOTIFY_MIN_LEVEL` | `info` | application-wide floor: `info`, `notice`, `important`, `critical` |
| `VAULT_NOTIFY_ADMIN_GROUP` | `admins` | Beacon group for `admin_security` |

## Protocol details that matter here

* Each request is a `GET` signed with HMAC-SHA256 (`X-OmniCore-Key`, `-Timestamp` within ±120 s, `-Nonce` single use for 6 minutes, `-User`, `-Signature`). **Every** failure (wrong method, unknown key, stale, replayed, forged, tampered) is the same `401 {"error":"unauthorized"}`; a request that fails the signature does not consume its nonce.
* Failures are reported as `omnicore_auth_failed` (`reason` is one of `method`, `body`, `unknown_key`, `timestamp`, `clock_skew`, `nonce`, `user`, `signature`, `replay`, `no_user`), at most one audit row a minute per address and 30 a minute in total, never with a key id or any header value. SkyNet sees it as `category: authentication`, `outcome: failure`.
* The routes sit outside the session, CSRF and origin checks (they carry no cookie and are never accepted with one) but behind the SkyNet deny list, the security headers and `Cache-Control: no-store`, with their own limit of 900 requests a minute per client address (`429` beyond it; OmniCore backs off).
* Widgets are cheap: counts, or one indexed lookup. The audit lookups use the index added by migration 4 (`audit_log(event, created_at)`).
* The code in `server/internal/omniconnect/` and `server/internal/notify/` is **vendored verbatim** from OmniCore's `reference/go`, with `testvectors.json` (the signature contract, in `omniconnect/testdata/`). Change it upstream, not here. TheVault's own code is `internal/omnicore` (provider) and `internal/alerts` (notifications).

## Tests

`server/internal/omniconnect` (vendored: signature vectors, rejection matrix, sanitiser), `server/internal/notify` (vendored), `server/internal/omnicore` (reason vocabulary, rate limit, method handling), `server/internal/store/omnicore_test.go` (read models), `server/internal/config` (settings), and in `server/internal/e2e/omnicore_test.go`: unsigned, forged, tampered, replayed, stale and wrong-key requests all get the identical `401`; unknown person is `403 not_linked`; every manifest widget answers and passes the sanitiser; the manifest validates; person A never receives person B's data; role-restricted widgets are `403` for a member, a demoted or locked person; widgets never contain ciphertext, names, tokens or e-mail addresses, never unlock a session and work while the vault is locked; notifications reach a fake Beacon with the right `source`, `category`, `level`, recipient and idempotency key, the mandatory flags are in the catalog, the floor is respected, nothing leaks, and a Beacon that is down or gone never slows or fails a request.
