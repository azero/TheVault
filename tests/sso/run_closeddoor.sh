#!/usr/bin/env bash
# Disposable installed ClosedDoor only: creates a synthetic user and two clients.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CD_DIR="${CLOSEDDOOR_DIR:?set CLOSEDDOOR_DIR to an installed disposable ClosedDoor}"
WORK="$(mktemp -d)"; CD_PID=""; VAULT_PID=""
trap 'kill $CD_PID $VAULT_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT
CD_PORT="${CD_PORT:-18590}"; VAULT_PORT="${VAULT_PORT:-18593}"
SSO="http://localhost:$CD_PORT"; VAULT="http://localhost:$VAULT_PORT"
(cd "$CD_DIR" && php -S "localhost:$CD_PORT" -t public public/index.php >"$WORK/closeddoor.log" 2>&1) & CD_PID=$!
for i in $(seq 1 50); do curl -fs "$SSO/.well-known/openid-configuration" >/dev/null 2>&1 && break; sleep .2; done
curl -fs "$SSO/.well-known/openid-configuration" >/dev/null
CLOSEDDOOR_DIR="$CD_DIR" php "$ROOT/tests/sso/seed_closeddoor.php" "$VAULT" >"$WORK/seed.json"
cid=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["client_id"])' "$WORK/seed.json")
secret=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["client_secret"])' "$WORK/seed.json")
(cd "$ROOT/server" && CGO_ENABLED=0 go build -o "$WORK/thevault" ./cmd/thevault)
VAULT_DATA_DIR="$WORK/data" VAULT_LISTEN="localhost:$VAULT_PORT" VAULT_PUBLIC_URL="$VAULT" VAULT_OIDC_ISSUER="$SSO" VAULT_OIDC_CLIENT_ID="$cid" VAULT_OIDC_CLIENT_SECRET="$secret" "$WORK/thevault" serve >"$WORK/vault.log" 2>&1 & VAULT_PID=$!
for i in $(seq 1 50); do curl -fs "$VAULT/healthz" >/dev/null 2>&1 && break; sleep .2; done
export VAULT SSO SEED="$WORK/seed.json" VAULT_DB="$WORK/data/vault.db"
node "$ROOT/tests/sso/real_closeddoor.mjs"
