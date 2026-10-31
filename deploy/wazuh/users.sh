#!/usr/bin/env bash
# One-shot setup of the local Wazuh stack, step 2: indexer users (ADR 0013).
#
# The official internal_users.yml ships demo users whose passwords are public
# (admin/SecretPassword, kibanaserver/kibanaserver, and four more). This file keeps
# only the two accounts the stack uses, with the passwords generated in .env
# (node dist/cli.js gen-secrets), hashed with the indexer's own bcrypt tool.
#
# The indexer reads this file only when it creates its security index, on its very
# first start: changing a password afterwards needs securityadmin (see the runbook).
set -euo pipefail
umask 077

OUT=/out/security/internal_users.yml
if [[ -f "$OUT" ]]; then
  echo "users already present, nothing to do"
  exit 0
fi
: "${WAZUH_ADMIN_PASSWORD:?missing from .env, run gen-secrets}"
: "${WAZUH_DASHBOARD_PASSWORD:?missing from .env, run gen-secrets}"

export JAVA_HOME=/usr/share/wazuh-indexer/jdk
# The tool logs noise on stderr (no network here, so no host name to resolve): keep only
# a line shaped like a bcrypt hash, and stop rather than write anything else.
hash() {
  local h
  h=$(bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$1" 2>/dev/null | grep -E '^\$2[aby]\$12\$.{53}$' | tail -n 1)
  [[ -n "$h" ]] || { echo "bcrypt hashing failed" >&2; exit 1; }
  printf '%s' "$h"
}

install -d -m 700 -o 1000 -g 1000 /out/security
cat > "$OUT" <<EOF
---
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "$(hash "$WAZUH_ADMIN_PASSWORD")"
  reserved: true
  backend_roles:
  - "admin"
  description: "Administrator (Bastion Academy local stack)"

kibanaserver:
  hash: "$(hash "$WAZUH_DASHBOARD_PASSWORD")"
  reserved: true
  description: "Wazuh dashboard service account"
EOF
chown 1000:1000 "$OUT"
chmod 400 "$OUT"
echo "users created"
