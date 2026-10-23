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
7. **Rollback.** Devices remember the highest key version per space and refuse older ones, but a malicious server can still serve an older revision of one item, or an old state to a device that never saw the newer one. Fixing this needs a signed manifest of item revisions; not built.
8. **Export**: plain exports exist (migration, audits). They need the master password again, are audited and alerted; `VAULT_DISABLE_PLAIN_EXPORT=1` removes them. A compromised client can export without reporting it, which is why the report is advisory.
8. **Extension sign-in id is public.** The manifest key is committed so the id is stable; anyone can load an unpacked extension with the same key. That gives them a client, not access: they still need ClosedDoor sign-in and the master password. For a managed fleet, force-install a build you signed and set `VAULT_EXTENSION_IDS` to its id.
