# Operations

## Settings (environment variables)

| Variable | Default | |
|---|---|---|
| `VAULT_PUBLIC_URL` | required | the address people use, no path; `https` unless localhost |
| `VAULT_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET` | required | the ClosedDoor app (confidential) |
| `VAULT_LISTEN` | `:8444` | |
| `VAULT_DATA_DIR` | `/data` | |
| `VAULT_EXTENSION_IDS` | empty | allowed Chrome extension ids (comma separated) |
| `VAULT_TRUSTED_IP_HEADER` | empty | header holding the client address behind a proxy (right-most entry trusted) |
| `VAULT_SKYNET_URL`, `_ENROLL_TOKEN`, `_KEY`, `_COMMAND_PUBKEY`, `_HOST` | empty | see [skynet.md](skynet.md) |
| `VAULT_RESPONSE_ALLOWLIST` | empty | CIDRs SkyNet may never make us block |
| `VAULT_UNLOCK_IDLE_MINUTES` | 15 | default auto-lock (people can set 1 minute to 8 hours) |
| `VAULT_AUDIT_RETENTION_DAYS` | 365 | |
| `VAULT_MAX_ITEMS_PER_USER` | 20000 | |
| `VAULT_DISABLE_PLAIN_EXPORT` | empty | `1` removes plain JSON/CSV export |
| `VAULT_API_ENABLED` | off | `true` turns on the [automation API](automation-api.md) (ClosedDoor API keys for scripts). Needs the three `VAULT_OIDC_*` variables, which the sign-in already requires |
| `VAULT_API_CACHE_SECONDS` | 0 | reuse ClosedDoor's answer about a key this long (0 = ask every time; at most 300; advice 30 or less: a revoked key keeps working that long) |
| `VAULT_API_RATE_PER_MINUTE` | 120 | automation API requests per key per minute |

Configuration errors stop the server at start-up with a message that names the variable.

## ClosedDoor setup

*Admin → Applications → Register*: **confidential**; redirect URI `https://<vault>/auth/callback`; post-logout URI `https://<vault>/login`. Grant access to everyone who may use the vault (everyone granted is a member). Add the role label `admin` for vault administrators. Nothing else is needed: scopes are `openid profile email`.

### Automation API (optional)

To let scripts administer TheVault (health checks, offboarding, incident response, audit export): set `VAULT_API_ENABLED=true`, then in ClosedDoor open *Admin → Applications → TheVault → API permissions* and paste the output of `docker exec thevault thevault api-scopes` (the same block is in [automation-api.md](automation-api.md)); create a key under *Admin → API keys* with the permissions it needs. The API never exposes vault content. Set `VAULT_TRUSTED_IP_HEADER` behind a proxy so the failure throttle sees real client addresses. In SkyNet, watch `api_auth_failed`, `api_forbidden`, `api_rate_limited` and `api_call`.

## First start

1. The data directory must be writable by uid 10002. 2. Start. 3. The first person to sign in creates their vault. 4. Make sure someone has the `admin` role in ClosedDoor.

## Health and logs

`GET /healthz` returns `ok`; the image has a `HEALTHCHECK`. Logs go to stdout and never contain secrets, proofs or tokens (they name the event, not the data). *Administration → Overview* shows counts, database size and SkyNet status.

## Backup and restore

`docker exec thevault thevault backup` writes `/data/backups/vault-<time>.db` (a consistent snapshot, mode 0600). Back up the whole `/data` directory including `keys/` (the pepper and the cookie key). A database restored **without** its `keys/pepper.key` can still unlock nobody: proofs are peppered, so every person would have to use their recovery key. The backup is ciphertext, but it also holds session hashes and the audit log: store it as carefully as a password database.

Restore: stop, put `vault.db` and `keys/` back, start. A build refuses to open a database written by a newer schema.

## Upgrading

Pull the new image and redeploy. Migrations are append-only and run at start-up. Update the extension package too (it is the same version): *Settings → Browser extension* always offers the matching one, shows its version and SHA-256, and the zip it serves carries `VAULT_PUBLIC_URL` as the suggested vault address, so set that correctly. People update by downloading again, replacing the files in their extension folder and pressing *reload* on the extension's card.

## Administration tasks

| Task | How |
|---|---|
| Someone left the company | Disable them in ClosedDoor (they lose access within five minutes while signed in, and cannot unlock again). Optionally *Lock* them in TheVault and *End sessions*. Spaces they owned keep working; they are removed by another owner (the UI then forces a key rotation). |
| Someone forgot their master password and lost the recovery key | *Administration → People → Erase vault* (you must type their email). They start over; their space memberships are gone. There is no other way, by design. |
| Suspected stolen session | *Lock* the person (ends every session), have them sign in again and change the master password. |
| Disable plain-text export | `VAULT_DISABLE_PLAIN_EXPORT=1` |
| Rotate the SkyNet key | create a new enrollment token, delete `/data/keys/skynet.json`, set `VAULT_SKYNET_ENROLL_TOKEN`, restart |
| Rotate the pepper | not supported (it would invalidate every proof; people would need their recovery key). Treat `keys/pepper.key` like a database credential. |

## Troubleshooting

| Symptom | Cause |
|---|---|
| "The sign-in service is not reachable" | the container cannot reach `VAULT_OIDC_ISSUER` (the server starts anyway and retries) |
| Sign-in loops back to `/login` | `VAULT_PUBLIC_URL` differs from the address in the browser, so the cookie is not sent, or the redirect URI registered in ClosedDoor does not match exactly |
| "Sign-in failed" right after ClosedDoor | the pre-login cookie was lost (a proxy stripping cookies, or two tabs racing); start again |
| Extension: "This vault does not know this copy of the browser extension" (sign-in window) or "TheVault does not know this extension yet" (popup) | the extension id shown is not in `VAULT_EXTENSION_IDS` |
| Extension: the address is pre-filled with the wrong host | `VAULT_PUBLIC_URL` is what the package suggests; fix it and restart (the package is rebuilt at start) |
| Settings → Browser extension says the build has no package | not the official image: run `npm run build:extension -- --embed` before `go build`, or load `extension/` unpacked |
| Extension: cannot reach the server | the address must be https (or localhost) and reachable from the browser; CORS is only granted to ids in `VAULT_EXTENSION_IDS` |
| Everyone is rate limited or blocked together | `VAULT_TRUSTED_IP_HEADER` is not set behind a proxy, so everyone shares the proxy's address |
| API calls answer 503 `authentication_unavailable` | TheVault cannot reach `VAULT_OIDC_ISSUER`, or ClosedDoor rejected the app's client id/secret (the log says which; the response never does) |
| API calls answer 401 for a key that exists | the key is expired, revoked, or not granted TheVault in ClosedDoor; or the value is not a `cdk_` key (extension tokens and access tokens are refused) |
| API calls answer 403 `forbidden` for a user key | the person lacks the `admin` role label for TheVault in ClosedDoor, or is locked in TheVault |
| API calls answer 429 | the per-key limit (`VAULT_API_RATE_PER_MINUTE`) or 20 failed authentications a minute from that address; see `Retry-After` |
| SkyNet shows no events | check *Administration → SkyNet* for the last error; the key may have been revoked in SkyNet |


### Grant-filtered navigation migration

Schema 3 appends `sessions.apps TEXT NOT NULL DEFAULT '[]'`. Existing sessions retain no navigation links until a verified SSO check or sign-in; the OIDC request now includes the `apps` scope. Preserve the pre-upgrade database/settings/key backup. An older binary refuses the newer schema, so image-only rollback is insufficient: recovery needs a reviewed compatible release or a separately authorized database restore that accounts for subsequent writes. Never edit an applied migration or silently restore over live data.
