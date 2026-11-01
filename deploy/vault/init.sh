#!/bin/sh
# Vault setup and unseal for the local stack (ADR 0019). Runs at every `up`:
#  - first run: initialise (1 key share), unseal, enable the audit log, Transit with one
#    derived, non-exportable key, the `bastion` policy, AppRole; write Bastion's role id
#    and secret id; then REVOKE the root token: nothing privileged survives setup.
#  - later runs: unseal only.
# The unseal key stays in the vault-keys volume, mounted by this container only. On a
# local install that is the trade-off (the operator is the learner); hosting replaces it
# with auto-unseal (cloud KMS or HSM), and the root token is regenerated with
# `vault operator generate-root` only when an operator needs it.
set -eu
umask 077
export VAULT_ADDR=http://vault:8200
KEYS=/vault-keys
OUT=/approle

# vault status: 0 unsealed, 2 sealed, 1 unreachable.
rc=1
for _ in $(seq 1 60); do
  rc=0
  vault status >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 1 ] && break
  sleep 1
done
if [ "$rc" -eq 1 ]; then
  echo "vault-init: Vault does not answer" >&2
  exit 1
fi

root=""
if [ ! -s "$KEYS/unseal.key" ]; then
  if vault status 2>/dev/null | grep -Eq '^Initialized +true'; then
    echo "vault-init: Vault is initialised but the unseal key is gone (vault-keys volume lost)" >&2
    exit 1
  fi
  # Kept in a variable, never written: the root token must not reach a disk.
  init=$(vault operator init -key-shares=1 -key-threshold=1)
  printf '%s\n' "$init" | awk '/^Unseal Key 1:/ {print $4}' > "$KEYS/unseal.key"
  root=$(printf '%s\n' "$init" | awk '/^Initial Root Token:/ {print $4}')
  init=""
fi

vault operator unseal "$(cat "$KEYS/unseal.key")" >/dev/null
echo "vault-init: unsealed"
[ -z "$root" ] && exit 0

export VAULT_TOKEN="$root"
# Integrated storage elects itself leader a moment after unsealing.
for _ in $(seq 1 30); do
  vault secrets list >/dev/null 2>&1 && break
  sleep 1
done

# Every request to Vault is logged (secrets HMAC-ed by Vault), to the container log.
vault audit enable file file_path=stdout >/dev/null
vault secrets enable transit >/dev/null
# derived: a key per context (note id), so a DEK only opens for its own note.
vault write -f transit/keys/bastion-kek type=aes256-gcm96 derived=true exportable=false allow_plaintext_backup=false >/dev/null
vault policy write bastion /setup/bastion-policy.hcl >/dev/null
vault auth enable approle >/dev/null
# Tokens live 1 hour (4 at most) and carry the bastion policy only.
vault write auth/approle/role/bastion \
  token_policies=bastion token_no_default_policy=true token_type=service \
  token_ttl=1h token_max_ttl=4h secret_id_ttl=0 secret_id_num_uses=0 >/dev/null
vault read -field=role_id auth/approle/role/bastion/role-id > "$OUT/role_id"
vault write -f -field=secret_id auth/approle/role/bastion/secret-id > "$OUT/secret_id"
# The platform runs as 65532 (distroless nonroot) and only reads them. chmod before chown:
# without CAP_FOWNER, root cannot change the mode of a file it no longer owns.
chmod 0400 "$OUT/role_id" "$OUT/secret_id"
chown 65532:65532 "$OUT/role_id" "$OUT/secret_id"

vault token revoke -self >/dev/null
echo "vault-init: Transit key, policy and AppRole ready; root token revoked"
