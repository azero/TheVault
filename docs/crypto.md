# Cryptography

This is the specification of **format v1**. The code is in `server/internal/web/static/js/core/` (one copy of it is shipped inside the extension). Anything that changes a parameter or a label below is a new format version (`v2`), never an edit to `v1`: existing vaults must keep opening.

## Goals

1. The server (and anyone with the database, a backup, the logs or the network) can **never read** an item, an item's name, URL, type or folder, or a space's name.
2. A person who holds a valid ClosedDoor session but **not** the master password cannot download ciphertext at all (the server refuses until a proof of the master password is presented), and cannot guess the password faster than the server's throttle allows.
3. A forgotten master password is recoverable by the person (recovery key) without any back door for the server or administrators.
4. Teams can share secrets in *spaces* with per-person keys, and removing someone really takes the key away from them.
5. Only primitives that browsers implement natively and that have been reviewed for years: **no hand-written crypto, no third-party crypto library**.

## Primitives (all WebCrypto)

| Use | Algorithm |
|---|---|
| Password to key | PBKDF2-HMAC-SHA256, 1,000,000 iterations by default, 600,000 minimum, 32-byte random salt per user |
| Key separation | HKDF-SHA256 (empty salt, a purpose string as `info`) |
| Encryption | AES-256-GCM, random 96-bit IV, 128-bit tag, **additional data on every envelope** |
| Key pairs | ECDH P-256 (receive shared keys) and ECDSA P-256 / SHA-256 (sign what you share), one pair of each per person |
| Hash | SHA-256 |
| One-time codes | HMAC-SHA1/256/512 (RFC 6238 / 4226) |
| Random | `crypto.getRandomValues`; integers by rejection sampling (no modulo bias) |

PBKDF2 was chosen over Argon2id because WebCrypto implements it natively in every browser and in extension service workers. The parameters are stored per user, so moving to Argon2id later is a re-wrap, not a migration of items. Clients **refuse** parameters below 600,000 iterations (a hostile or buggy server cannot downgrade them) or above 20,000,000 (nor freeze the browser).

## Key hierarchy

```
master password ──NFKC──PBKDF2(salt, N)──▶ MK  (32 bytes, never leaves the client, wiped after use)
                                            │
                          ┌─────────────────┴──────────────────┐
              HKDF "thevault/v1/enc"                HKDF "thevault/v1/auth"
                          │                                     │
                    enc key (AES)                     auth proof (32 bytes) ──▶ sent to the server
                          │
          wraps ──▶  UK  user key (random 256 bit AES key)
                          │  ├── encrypts every personal item
                          │  ├── wraps the ECDH private key and the ECDSA private key
                          │  └── (also wrapped independently by the recovery key)
recovery key (random 256 bit, shown once) ──HKDF "…/recovery-enc"──▶ wraps UK
                                          ──HKDF "…/recovery-auth"──▶ recovery proof ──▶ sent to the server
space key (random 256 bit, one per space and key version) ── encrypts the space's items and name
                          └── wrapped per member with ECDH(ephemeral, member public key), signed by the sharer
```

Changing the master password re-wraps UK; no item is re-encrypted. A new recovery key re-wraps UK as well. Rotating a *space* key re-encrypts that space's items (see below).

## Envelope

Every ciphertext is a string `1.<iv>.<ciphertext+tag>` (base64url, no padding). The *additional authenticated data* (AAD) is not stored; it is rebuilt from context, so a ciphertext only opens where it belongs:

| What | AAD |
|---|---|
| User key under the master key | `thevault/v1/uk` |
| User key under the recovery key | `thevault/v1/uk-recovery` |
| ECDH / ECDSA private keys (PKCS#8) under UK | `thevault/v1/enc-priv`, `thevault/v1/sig-priv` |
| Item | `thevault/v1/item\|<vault id>\|<item id>\|<key version>` |
| Space name | `thevault/v1/space-name\|<space id>\|<key version>` |
| Space key for one member | `thevault/v1/share\|<space id>\|<key version>\|<member sub>` |
| Encrypted export file | `thevault/v1/export` |

Because the item id, its vault and the key version are in the AAD, **the server cannot swap two items, move an item into another vault, or replay an old version under a new key** without the client noticing (decryption fails). Failures are deliberately indistinguishable ("decryption failed").

## Account creation (client, before anything is sent)

1. Random 32-byte `salt`; derive MK; derive `enc key` and `auth proof`.
2. Random UK. Two key pairs (ECDH, ECDSA); their private halves are sealed under UK.
3. Random 256-bit recovery key; derive `recovery enc key` and `recovery proof`; seal UK under it.
4. Show the recovery key (52 Crockford-base32 characters plus two check characters, in groups of six). The person must confirm they saved it **before** `POST /api/v1/vault/setup` is sent, so a vault never exists without a saved recovery key.
5. Send: KDF parameters, `auth proof`, sealed UK, public keys, sealed private keys, recovery proof, UK sealed under the recovery key.

## Unlock

`GET prelogin` returns the KDF parameters (only to a signed-in person). The client derives `auth proof`, sends it to `POST unlock`, and only after the server accepts it receives the sealed UK and the sealed private keys. It opens them locally; a wrong password never gets this far, and the server cannot tell whether the client could decrypt.

The server stores `HMAC-SHA256(pepper, "thevault/proof/v1\0" ‖ proof)`, never the proof, with a pepper from `/data/keys/pepper.key`. The proof is a 256-bit HKDF output, so the server-side check cannot be brute-forced, and the pepper keeps a stolen *proof hash* useless. **It does not protect the master password against someone who has the database:** `wrapped_uk` and the salt are stored too, and AES-GCM tells an attacker whether a guess opened the wrap, so offline guessing needs only the database and costs one PBKDF2 run (1,000,000 iterations by default) per guess. The strength of the master password is therefore the only thing between a stolen database and the vault; the UI enforces a minimum length and shows a strength meter, and the generator makes passphrases easy.

## Recovery

`recovery/start` takes the recovery proof (throttled; five wrong keys lock recovery for an hour) and returns UK sealed under the recovery key. The client opens it, asks for a new master password, re-wraps UK, **creates a new recovery key** and sends everything to `recovery/finish`, which also ends all other sessions. The recovery key has 256 bits and the server only holds an HMAC of its proof, so there is no way for the server to use it.

If the master password *and* the recovery key are lost, the data is gone: an administrator can erase the vault (audited), after which the person starts over.

## Sharing: spaces

* A space has a random 256-bit **space key** per *key version*. Items in the space and the space's name are encrypted with it (AAD above).
* To add a member, an owner's client generates an **ephemeral ECDH key pair**, computes `ECDH(ephemeral private, member public)`, derives an AES key with HKDF (`info` = the share AAD) and seals the space key. The wrap is then **signed with the owner's ECDSA key** over `thevault/v1/share-sig\n<space>\n<version>\n<member sub>\n<ephemeral public>\n<ciphertext>`. The server stores `{eph, ct, sig, by}`.
* The recipient verifies the signature before it opens the wrap, and **the verifying key is never one the server merely names**: for a wrap made by someone else it must match the fingerprint pinned the first time that person was seen (trust on first use; a change is refused until the user accepts the new fingerprint in *Spaces → Manage*), and for a wrap we made ourselves it is our own signing key. Our own public keys are derived from the private keys we just opened, and the unlock is refused if the server sent different ones, so a lying server cannot show two people the same fake fingerprint. A malicious server therefore cannot hand someone a space key *it* chose, and cannot replay a wrap to another user or key version. The role is deliberately *not* signed: the server enforces roles and every member holds the key anyway, so signing it would only break a wrap whenever a role changes.
* Before wrapping a key for another person (adding a member, rotating) the client compares their current public keys with the pinned fingerprint and refuses on a mismatch, so a key swapped after first contact does not receive the new space key.
* When an account's vault is erased, its public keys are kept in `retired_keys` (no secrets) and the wraps it made stay verifiable; every space it belonged to is flagged for rotation, and a space left without an owner promotes its longest-standing member.
* **Rollback.** Each device remembers the highest key version it has seen per space and refuses an older state. Beyond that, a malicious server could still serve an older revision of a single item (the AAD binds id, vault and key version, not a revision) or, on a device that has never seen the space, an older key version. Closing this fully needs a signed manifest and is listed as a known limitation in the threat model.
* **Trust on first use.** The first time a client sees a sharer's public keys it pins their **fingerprint** (20 bytes of SHA-256 over both public keys, ten groups of four hex digits). A later change is refused until the person accepts it in Space settings. Owners should compare fingerprints out of band for sensitive spaces. A server that substitutes keys *before* the first contact is the residual risk (see the threat model).
* **Removing a member** flags the space `needs_rotation`; the UI forces the owner to **rotate**: a fresh space key, every item and the name re-encrypted, a new wrap for every remaining member, all in one atomic request that the server accepts only if it covers *exactly* the live items (at the revisions the owner saw) and exactly the current members. Until then no one can be added. Old item versions are deleted because they cannot be decrypted any more.
* Roles (`owner`, `editor`, `viewer`) are enforced by the server for writes. Viewers hold the key (they must, to read) so the role limits what the *server* accepts, not what a malicious viewer's own client could do with the data it can already read.

## Export file

`{ "format": "thevault-export", "v": 1, kdf, iterations, salt, data }`: PBKDF2 of a password chosen at export time, HKDF `thevault/v1/export-enc`, AES-256-GCM over the JSON. Import enforces the same iteration bounds.

## What the server stores and learns

| Stored | Content | Server can read? |
|---|---|---|
| `items.blob` | AES-GCM envelope of the item JSON | no |
| `items.id`, `vault_id`, `seq`, `key_version`, timestamps | random ids, counters | yes |
| `vault_keys.wrapped_uk`, sealed private keys | envelopes | no |
| `vault_keys.enc_pub`, `sig_pub` | public keys | yes (public) |
| `vault_keys.auth_hash`, `recovery_hash` | peppered HMAC of proofs | not reversible |
| `spaces.name_blob`, wraps | envelopes | no |
| Sizes and counts, who shares with whom, when items change | metadata | yes |

It does **not** learn: item names, URLs, usernames, passwords, notes, tags, folders, item types, the master password, the recovery key, space names.

## Memory handling

Unlocked material lives only in JavaScript memory (web app) or in `chrome.storage.session` (extension, memory-only, cleared at browser close). Raw key bytes are zeroed after use where the platform allows; `CryptoKey` objects are non-extractable except the user key, which must be extractable to be re-wrapped. Nothing derived from the master password is ever written to `localStorage`, `sessionStorage`, IndexedDB or cookies (the browser test asserts this).

## Tests

`tests/js/*.test.mjs` cover: base64url strictness; envelope round trips and tamper/AAD/truncation failures; KDF bounds; unlock, password change and recovery (including typo detection in the recovery key); AAD binding of items; space key wrap, wrong recipient, forged sender, altered version, replay to another user, sharer pinning and a server naming its own signing key, public keys derived from the private keys; TOTP against the RFC 6238 and RFC 4226 vectors; generator distribution; URL matching including phishing look-alikes; CSV import/export; encrypted export.
