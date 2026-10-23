# SkyNet integration

TheVault is a SkyNet **adapter** (the same wire protocol as SkyNet's PHP adapter): it ships events out and obeys signed `block_ip` commands.

## Connect it

1. In SkyNet: **Agents → Create enrollment token**, type **PHP / web adapter** (or `skynet enroll-token -kind adapter`).
2. Set in TheVault's environment: `VAULT_SKYNET_URL=https://skynet.example.com` and `VAULT_SKYNET_ENROLL_TOKEN=skyenr_…` (and `VAULT_SKYNET_HOST` for the host label).
3. Start TheVault. It enrolls once, stores `{url, api_key, agent_id, command_pubkey}` in `/data/keys/skynet.json` (mode 0600), and logs `skynet: enrolled as agt_…`. Remove the token from the environment afterwards.
   * Already have an agent key? Use `VAULT_SKYNET_KEY=<id>.<secret>` plus `VAULT_SKYNET_COMMAND_PUBKEY=<base64 Ed25519 key>`. Without the command key TheVault still ships events but refuses all commands.
   * If enrollment is refused, the server **does not start**: a security tool that silently runs unmonitored is worse than one that fails loudly.
4. Run a SkyNet build that contains `server/rules/thevault.yml` (it is part of SkyNet's built-in rules). Put your offices, ClosedDoor, SkyNet and your reverse proxy in **`VAULT_RESPONSE_ALLOWLIST`** (CIDRs) so they can never be blocked.

*Administration → SkyNet* in TheVault shows the connection, queue depth, last send, dropped events, command status and the current deny list.

## Events

Every audit event is also a SkyNet event ([security.md](security.md) lists them): `source: thevault`, `category` (`authentication`, `iam`, `vault`, `web`, `system`), `action`, `outcome`, `user` (the email if it is a valid address, else `uid:<sub>`), `src_ip`, and `fields` (`sub`, `target` = an item/space/session id, `user_agent`, counts such as `items`). **Never** anything from a blob, no proof, no password, no item name.

* Delivery: events are queued in memory, written to a bounded SQLite outbox (50,000 rows; oldest dropped first), and sent as gzip NDJSON every few seconds or on a burst, with exponential back-off up to 5 minutes. A SkyNet outage loses nothing within the cap, and never slows a request (the audit call does not wait for the network).
* Automation API events (when `VAULT_API_ENABLED`): `api_auth_failed` (`authentication`), `api_forbidden` (`authorization`), `api_rate_limited` (`web`), `api_call` (`iam` for accounts and sessions, `system` for the audit log and block list). `user` is the person's email (else `sub`) for a user key and `key:<key name>` for a service key; `fields` carry `key_id`, `key_name`, `principal`, `scope`, `method`, `target`, `status`, `reason`, `needs`, `limit`, never a credential. Details: [automation-api.md](automation-api.md#what-reaches-the-audit-log-and-skynet).
* `heartbeat` every minute (`version`, `outbox`) lets SkyNet's silent-agent alert catch a dead or cut-off vault. `events_dropped` reports queue overflow.

## Detection rules shipped in SkyNet (`server/rules/thevault.yml`)

| Rule | Fires on | Severity |
|---|---|---|
| `skynet-vault-unlock-bruteforce-user` | ≥ 5 wrong master passwords for one account in 10 min | high |
| `skynet-vault-unlock-bruteforce-ip` | ≥ 10 from one address in 10 min (has a `block_ip` response, **off** until you set `auto: true`) | high |
| `skynet-vault-lockout` | TheVault's own lockout | medium |
| `skynet-vault-recovery-used` / `recovery-guessing` | a recovery key used / ≥ 3 wrong in an hour | high |
| `skynet-vault-plain-export` | unencrypted export | high |
| `skynet-vault-mass-delete` | ≥ 20 deletions in 5 min | high |
| `skynet-vault-repeated-full-download` | ≥ 6 full syncs in 10 min | medium |
| `skynet-vault-request-probing` | ≥ 5 CSRF/origin/bearer refusals from one address in 5 min | medium |
| `skynet-vault-admin-action` | lock/unlock/revoke/erase by an admin | medium |
| `skynet-vault-denied-signin` | a locked account tries to sign in | medium |
| `skynet-vault-session-address-changed`, `new-extension-device`, `master-password-changed`, `blocked-still-trying` | context for investigations | low |

Each rule carries test fixtures that SkyNet's CI runs.

### Turn on automatic blocking

Run in dry-run for a while (SkyNet's *Response* page). Then override the rule in `/data/rules/` on the SkyNet side:

```yaml
id: skynet-vault-unlock-bruteforce-ip      # same id replaces the built-in
title: Wrong master passwords from one address across TheVault accounts
severity: high
detection: { fails: { source: thevault, action: unlock_failed, 'src_ip|exists': true }, condition: fails }
threshold: { count: 10, window: 10m }
group_by: [src_ip]
response: { action: block_ip, field: src_ip, ttl: 1h, scope: agent, auto: true }
```

## Signed commands

TheVault long-polls `GET /api/v1/commands?wait=25` and, for each command, **verifies before acting**:

1. Ed25519 signature over `"skynet-cmd-v1\n" ‖ payload` with the public key pinned at enrollment (or `VAULT_SKYNET_COMMAND_PUBKEY`); a bad signature is dropped silently and never reported;
2. `v == 1`, `agent_id` is this adapter, not expired, not issued in the future (±2 min), validity window ≤ 15 minutes;
3. the command id has not been seen (recorded in SQLite **before** acting, so a crash cannot cause a second execution);
4. only `block_ip` and `unblock_ip` are supported (`kill_process`/`isolate` are reported as skipped);
5. `block_ip`: the address must be blockable. **Never** loopback, unspecified, link-local, multicast, broadcast, SkyNet's own address(es), or anything in `VAULT_RESPONSE_ALLOWLIST`. IPv4-mapped IPv6 is normalised. TTL 1 minute to 7 days.
6. `dry_run` commands are reported (`skipped: dry-run: would deny …`), never executed.

An address on the deny list gets a bare **HTTP 403 before anything else runs** (including the sign-in page and the API), except `/healthz`. The result is reported back to SkyNet and a `response_applied` event is emitted. Entries expire by themselves and survive restarts (`deny_list` table).

**Behind a proxy**, set `VAULT_TRUSTED_IP_HEADER` (for example `X-Forwarded-For`; only the right-most entry is trusted). If you do not, every visitor looks like the proxy: SkyNet might ask to block the proxy's address, and the never-block list is your safety net, so put the proxy's address range in `VAULT_RESPONSE_ALLOWLIST`.

## Also protect the host

Install SkyNet's endpoint agent (Windows) on machines that run browsers with the extension, and keep the vault host itself monitored. TheVault's events tell SkyNet what happened *inside* the app; the agent and its rules tell it what happened around it.
