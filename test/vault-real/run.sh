#!/usr/bin/env bash
# KEKs in the real Vault (ADR 0019), end to end, with docker-compose.vault.yml:
#  1. the platform starts on the local ring and stores a note and a TOTP seed;
#  2. it restarts with Vault: the old rows still open (local ring kept for reading), new
#     ones go to Vault; `rotate-keys` moves everything into Vault, then re-wraps inside it;
#  3. Bastion's AppRole token is refused everything its policy does not grant (export,
#     key config, deletion, other paths), and the root token no longer exists;
#  4. a sealed Vault answers 503 (not the tampering alert) until it is unsealed again.
# Needs the platform image: docker build -t bastion:local .   (or APP_IMAGE=...)
# Uses its own compose project and volumes, removed at the end. Run: test/vault-real/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
# Windows (Git Bash): docker is a Windows program, give it C:/... paths (forward slashes survive sed).
host() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
APP_IMAGE=${APP_IMAGE:-bastion:local}
P=bastion-vault-e2e
work=$(host "$(mktemp -d)")
export GRAFANA_ADMIN_PASSWORD=unused-here

# The main file with the image under test and throwaway secrets; paths stay relative to the repository.
sed -e "s|image: bastion:local|image: $APP_IMAGE|" -e "s|env_file: .env|env_file: $(host "$work")/e2e.env|" docker-compose.yml > "$work/compose.yml"
node dist/cli.js gen-secrets > "$work/e2e.env"
local_dc() { docker compose -p $P --project-directory . -f "$(host "$work/compose.yml")" "$@"; }
vault_dc() { docker compose -p $P --project-directory . -f "$(host "$work/compose.yml")" -f docker-compose.vault.yml "$@"; }
cleanup() { vault_dc down -v >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
vault_dc down -v >/dev/null 2>&1 || true

ok() { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; exit 1; }
api() { curl -s -o "$(host "$work/body")" -w '%{http_code}' -H 'Content-Type: application/json' "$@"; }
wait_up() {
  for _ in $(seq 1 60); do curl -fs http://127.0.0.1:3000/healthz >/dev/null 2>&1 && return 0; sleep 1; done
  fail "platform did not start"
}
field() { node -e 'const b=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));console.log(b[process.argv[2]] ?? "")' "$work/body" "$1"; }
sql() { vault_dc exec -T bastion /nodejs/bin/node -e "const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync('/data/bastion.db',{readOnly:true});console.log(JSON.stringify(db.prepare(process.argv[1]).all()))" "$1" 2>/dev/null; }

# 1. Local ring.
local_dc up -d --no-build bastion >/dev/null 2>&1
wait_up
api -X POST http://127.0.0.1:3000/v1/auth/register -d '{"email":"kms@example.test","password":"correct horse battery staple"}' >/dev/null
[ "$(api -X POST http://127.0.0.1:3000/v1/auth/login -d '{"email":"kms@example.test","password":"correct horse battery staple"}')" = 200 ] || fail "login"
AUTH="Authorization: Bearer $(field accessToken)"
api -X POST http://127.0.0.1:3000/v1/notes -H "$AUTH" -d '{"title":"before","body":"written under the local ring"}' >/dev/null
OLD=$(field id)
api -X POST http://127.0.0.1:3000/v1/me/mfa/setup -H "$AUTH" -d '{"password":"correct horse battery staple"}' >/dev/null
ok "local ring: a note and a TOTP seed stored"

# 2. Vault.
vault_dc up -d --no-build bastion >/dev/null 2>&1
wait_up
vault_dc logs vault-init 2>/dev/null | grep -q 'root token revoked' && ok "Vault initialised, root token revoked"
[ "$(api http://127.0.0.1:3000/v1/notes/"$OLD" -H "$AUTH")" = 200 ] && [ "$(field body)" = "written under the local ring" ] || fail "old note after the switch"
ok "a row of the local ring still opens (ring kept for reading)"
api -X POST http://127.0.0.1:3000/v1/notes -H "$AUTH" -d '{"title":"after","body":"written under Vault"}' >/dev/null
NEW=$(field id)
sql "SELECT key_id FROM notes WHERE id = '$NEW'" | grep -q '"vault:bastion-kek:v1"' || fail "new note not under Vault"
ok "a new note is wrapped by Vault (vault:bastion-kek:v1)"

vault_dc exec -T bastion /nodejs/bin/node dist/cli.js rotate-keys | tail -1
[ "$(sql "SELECT DISTINCT key_id FROM notes UNION SELECT DISTINCT key_id FROM user_mfa")" = '[{"key_id":"vault:bastion-kek:v2"}]' ] || fail "rows not all under v2: $(sql 'SELECT key_id FROM notes')"
ok "rotate-keys: every note and seed under vault:bastion-kek:v2"
for id in "$OLD" "$NEW"; do [ "$(api http://127.0.0.1:3000/v1/notes/"$id" -H "$AUTH")" = 200 ] || fail "note $id after rotation"; done
ok "both notes open after the rotation"

# 3. The policy, with Bastion's own credentials.
vault_dc run --rm -T --no-deps --user 65532:65532 --entrypoint sh -v "${P}_vault-approle:/a:ro" vault-init -c '
  export VAULT_ADDR=http://vault:8200
  VAULT_TOKEN=$(vault write -field=token auth/approle/login role_id="$(cat /a/role_id)" secret_id="$(cat /a/secret_id)") || exit 1
  export VAULT_TOKEN
  vault read transit/keys/bastion-kek >/dev/null || { echo "FAIL  cannot read the key metadata"; exit 1; }
  for cmd in "read transit/export/encryption-key/bastion-kek" "write transit/keys/bastion-kek/config min_decryption_version=2" \
             "delete transit/keys/bastion-kek" "read transit/backup/bastion-kek" "secrets list" "policy list" "token create"; do
    # Refused by the policy (403), not merely failing for another reason.
    if vault $cmd >/tmp/out 2>&1 || ! grep -q "permission denied" /tmp/out; then echo "FAIL  not denied by policy: vault $cmd"; cat /tmp/out; exit 1; fi
    echo "ok    denied by policy: vault $cmd"
  done' || fail "policy"

# 4. Sealed.
vault_dc restart vault >/dev/null 2>&1
sleep 3
code=$(api http://127.0.0.1:3000/v1/notes/"$OLD" -H "$AUTH")
[ "$code" = 503 ] || fail "sealed Vault answered $code"
ok "sealed Vault: 503, not 500"
vault_dc run --rm -T vault-init >/dev/null 2>&1
[ "$(api http://127.0.0.1:3000/v1/notes/"$OLD" -H "$AUTH")" = 200 ] || fail "after unseal"
ok "unsealed again: notes open"
vault_dc logs bastion 2>/dev/null | grep -q 'ciphertext integrity failure' && fail "an outage raised the tampering alert"
ok "no integrity alert during the outage"
echo "Vault KMS end to end: all checks passed"
