# Threat model

## What we protect

The *contents* of everyone's vault (secrets, names, URLs, notes) and the *availability* of that data for its owner. Metadata (who has a vault, when they unlock, how many items, who shares with whom) is visible to the server and to administrators by design.

## Attackers and outcomes

| Attacker | Can they read vault contents? | Notes |
|---|---|---|
| Steals the database, a backup or the disk | **No** | Ciphertext, sealed keys, peppered proof hashes. The pepper does not stop offline guessing of the master password: the sealed user key and salt are in the database, so a guess costs only 1,000,000 PBKDF2 iterations. A long master password is the protection. |
| Steals the database **and** `/data/keys` | Only by guessing master passwords offline | Same cost per guess; recovery keys (256-bit) are out of reach. This is the standard limit of any password-derived key. |
| Reads server logs, memory dumps, SkyNet events | **No** | No secret or proof is ever logged; events carry ids, counts and addresses. A memory dump of a *running* server holds session hashes and ciphertext, not keys. |
| Malicious or compromised administrator | **No** | No route returns content. They can lock accounts and erase vaults (audited, alerting). |
| Active malicious server (code changed, or a rogue operator) | **Only by serving hostile JavaScript** | The web app is served by the server, so a server that ships modified JS can steal master passwords as they are typed. This is inherent to any web-delivered E2E app. The extension's code is fixed at install time; prefer it for sensitive use, pin the extension build, and monitor the image. |
| Network attacker | No | TLS terminated at the proxy; HSTS; the app refuses an `http://` public URL except localhost. |
| Someone with a stolen ClosedDoor session (not the master password) | **No** | Needs the master-password proof before any ciphertext is released; throttled and alerted. They can see metadata. |
| Someone with a stolen *unlocked* browser session | Yes, for the unlock window | Idle lock (15 min default), lock on screen lock (extension), device list with remote sign-out, `session_ip_changed` and `sync_full` events. |
| Malware on the person's computer | Yes | Out of scope: it can read the screen, keystrokes and memory. The extension keeps decrypted data out of disk storage. |
| Phishing page trying to get the extension to fill | **No** | Exact host matching, https only, top frame and frame must match, visible fields only, user action required. |
| Malicious web page trying to drive the web app (XSS/CSRF/clickjacking) | No | Strict CSP + Trusted Types, CSRF header + origin checks, `frame-ancestors 'none'`. |
| A removed space member | Not future changes | They keep what they already downloaded. Removal forces key rotation, so new and re-encrypted items need a key they never had. |
| Someone who steals or abuses an **API key** (automation API) | **No** | A key can never be unlocked, and the API has no route that returns vault content, ciphertext or key material. They can read personal data and the audit trail (per permission) and, with `users:lock`/`sessions:revoke`, disrupt accounts. See "Automation API" below. |
| A malicious space member | Everything in that space | By definition of sharing. Viewers can read; roles limit what the *server* accepts. |

## Assumptions

* ClosedDoor correctly authenticates people and honours its per-app grant.
* WebCrypto implementations are correct.
* The reverse proxy terminates TLS with a valid certificate and passes the client address in `VAULT_TRUSTED_IP_HEADER` (only the right-most entry is trusted).
* People choose a strong master password. TheVault enforces a 12-character minimum and refuses obviously weak ones, but cannot make them good.

## Known limits (decisions, not oversights)

1. **Server-delivered JavaScript** (above). Mitigations: strict CSP, no third-party code, pinned image, extension for sensitive use.
2. **Key substitution before first contact.** A malicious server could present its own public key when two people first share a space. Mitigation: TOFU pinning plus visible fingerprints; compare them out of band for sensitive spaces.
3. **Metadata is visible** (counts, timing, who shares with whom).
4. **No 2FA on the master password itself.** ClosedDoor sign-in is the first factor; the master password is the second, independent secret.
5. **ClosedDoor has no refresh tokens or back-channel logout.** Revocation reaches TheVault within five minutes while the SSO token is valid; an unlocked session may outlive its token by up to two hours (then must unlock again), and new unlocks need a fresh token.
6. **Clipboard**: clearing is time-based and unconditional once the delay passes.
7. **Browser features outside our control.** Secret fields in the editor are masked text inputs (not `type=password`) so Chrome does not offer to save API keys and card numbers in its own password manager; the master password field has to be a real password field. Spellcheck is off on secret fields and notes. The web clipboard is cleared by timer, on focus, on lock and on page close, but a browser cannot clear it while the tab is in the background; the extension clears it through an offscreen document (Chrome limits that timer to 30 s).
8. **Rollback.** Devices remember the highest key version per space and refuse older ones, but a malicious server can still serve an older revision of one item, or an old state to a device that never saw the newer one. Fixing this needs a signed manifest of item revisions; not built.
9. **Export**: plain exports exist (migration, audits); spreadsheet-formula cells in the CSV are prefixed with an apostrophe (import strips it). They need the master password again, are audited and alerted; `VAULT_DISABLE_PLAIN_EXPORT=1` removes them. A compromised client can export without reporting it, which is why the report is advisory.
10. **Extension sign-in id is public.** The manifest key is committed so the id is stable; anyone can load an unpacked extension with the same key. That gives them a client, not access: they still need ClosedDoor sign-in and the master password. For a managed fleet, force-install a build you signed and set `VAULT_EXTENSION_IDS` to its id.

## Automation API

Optional ([automation-api.md](automation-api.md)); scripts authenticate with ClosedDoor API keys. The design question is what a script may be allowed to do in a zero-knowledge system.

**Rule: an API key sees what an administrator sees, and no more; and what an administrator sees contains no vault content.** The server can only read or write vault data for a session that has been *unlocked* with a proof derived from the master password (security invariant 3), and an API key has no master password. The API is therefore an administration and operations interface, and it is built so that compromise or misuse of a key, or of every key, cannot disclose a secret:

* No route returns an item, folder, tag, note, space name or content, ciphertext, a wrapped or public key, a salt or KDF parameter, a proof or recovery data. No export or backup download exists; backups are listed by name, size and time only. A test seeds a vault with recognisable values and fetches every endpoint with every permission and as an administrator's user key.
* The new metadata the server shows is **already visible to administrators** in the administration screens (accounts, roles, lock state, sign-in times, session counts, audit rows, SkyNet status); the API adds no new kind of metadata. Where the screen shows more than automation needs (item and space counts per person, user-agent strings, full item ids) the API leaves it out or shortens it (ids of items and spaces are cut to 12 characters in audit rows, as in the screen). Session listings carry no tokens.
* Erasing a vault, creating or deleting accounts, changing roles, SkyNet blocks and master-password operations are not exposed: they are irreversible or belong to other systems.

**Attackers considered**

| Attacker | Outcome |
|---|---|
| Steals a key (leaked script, CI log) | Can do exactly what the key's permissions allow, nothing in the vault. Limit by granting least permissions, short expiries and one key per integration; revoke in ClosedDoor (effective on the next request, or within `VAULT_API_CACHE_SECONDS`). Every use is audited with the key id and sent to SkyNet. |
| Guesses keys | Keys are 256-bit random. Failed attempts are throttled per address (20 a minute) before ClosedDoor is asked, and reported to SkyNet (`api_auth_failed`). |
| Floods the API | Per-key limit (before ClosedDoor is asked), per-address failure throttle, 15 s deadline, 1 MB bodies, SkyNet blocks apply to the API too. |
| Abuses a person's *user key* | Authority is permission AND role: the person must hold the `admin` label (read live from ClosedDoor) and not be locked, so a demoted, disabled or locked person's key stops being useful at once. |
| Locks everyone out | Needs `users:lock`. Locking the caller (user keys) and the last active administrator is refused; unlocking is a separate permission; every call is audited and alerts via SkyNet (`admin_user_locked` and `api_call`). |
| Browser-based attack on the API | No cookies are accepted (nothing ambient to ride on), no CORS (a page cannot read a response), no CSRF token needed or accepted; the web UI in turn refuses `cdk_` keys. |
| Impersonates ClosedDoor (network) | Verification calls go to `VAULT_OIDC_ISSUER`, which must be https (loopback excepted), with the app's own client secret in an Authorization header. If ClosedDoor cannot be reached or rejects TheVault, requests get 503: it never fails open. |

**Residual risks (decisions)**

1. A key with `audit:read` or `users:read` discloses personal data (emails, addresses, the security trail). That is why they are separate, audited permissions.
2. A cache (if enabled) keeps a revoked key alive for at most `VAULT_API_CACHE_SECONDS` (advice: 30 or less; default 0).
3. The "last active administrator" guard uses the role recorded at each person's last sign-in; it is a safety net against a script locking everyone, not a substitute for least-privilege keys.
4. API traffic shares a process, a database and the rate limits' memory with the web app; the limits above bound what it can cost.

## OmniCore integration

Optional ([omnicore.md](omnicore.md)). **Security-review note for hard constraint 1**: the integration adds **no new kind of metadata** to what the server stores or shows. The widgets are a second way to see what administrators' screens and the person's own screens already show: counts (items in the personal vault and trash, spaces, spaces needing rotation, accounts, sessions), timestamps (vault created, last unlock, last seen), the labels the person gave their own sessions, audit event names, and SkyNet's deny list. It never touches ciphertext, wrapped or public keys, salts, proofs, tokens, item/folder/space names (all encrypted) or other people's addresses. The only schema change is an index (`audit_log(event, created_at)`) and one extra audit detail (`replaced` on `ext_device_added`). Notifications to Beacon (a new place metadata goes) carry only events about the recipient's own account (and anonymous operational events for administrators), as listed in [omnicore.md](omnicore.md).

| Attacker | Outcome |
|---|---|
| Steals the OmniCore signing key | Can read the widget data of any person who has signed in to TheVault: counts, times, their own device labels, event names, and (for an administrator's `sub`) operational numbers. **Cannot read, list or unlock vault content**: no widget touches it, and a signed request never creates or uses an unlocked session. Cannot write anything (GET only). Every use is signed per request, so it needs the secret, not a stolen request. Rotate by listing two keys; guessing is infeasible (256-bit secrets, 32 bytes minimum enforced) and failures are audited and sent to SkyNet (`omnicore_auth_failed`). |
| Replays or alters a captured request | Refused: timestamp window ±120 s, single-use nonce for 6 minutes, method, exact target and the person's `sub` are all inside the signature; a request that fails the signature does not use up a nonce. |
| Floods the endpoints | 900 requests a minute per address, then `429`; audit rows from failures are thinned per address and in total, so a flood cannot fill the audit table. |
| Compromised or malicious OmniCore | Same as a stolen key. It can show wrong numbers to people, but TheVault never acts on anything OmniCore says. |
| Reads Beacon's messages | Learns that an extension was authorised, a password changed, a recovery key used, wrong passwords entered, a person was added to a space, or an address blocked, with the person's ClosedDoor `sub` as recipient and the originating address. Nothing about names or content. |
| Uses TheVault to spam a person with alerts | `unlock_failed` is limited to one message per person per 15 minutes; the other security categories require an authenticated action on that account (a new device needs ClosedDoor sign-in; a password change needs the old master password). |

**Residual risks (decisions)**

1. **Administrator role is not re-confirmed live.** TheVault's own admin routes need a fresh ClosedDoor token; a signed OmniCore request carries none. The role is the one recorded at the person's last sign-in, overridden downwards by any live session that ClosedDoor has re-validated to a lower role. A person whose `admin` label was removed in ClosedDoor and who has no live TheVault session keeps seeing the four administrator widgets (operational counts and the blocked addresses, nothing about people) until they next sign in. OmniCore applies its own role check as well. Accounts locked or removed from the app's grant in TheVault are refused.
2. A person whose ClosedDoor grant for TheVault was removed, but who has never been locked in TheVault, can still see their own widgets (their own metadata) until their next sign-in is refused. They can read nothing that is not already theirs.
3. Notifications are best effort: queued in memory, retried a few times, dropped if Beacon stays down. They are advisory; the audit log and SkyNet remain the record.
