#!/usr/bin/env bash
# One-shot setup of the local Wazuh stack, step 1: TLS certificates (ADR 0013).
#
# Generated here with openssl, offline (the container has no network), instead of
# the official generator image, which downloads its certificate tool from the
# Internet at every run with no pinned version: code we would execute unseen.
#
# Idempotent: an existing CA is kept, so a second run changes nothing.
set -euo pipefail
umask 077

OUT=/out
SUBJ="/C=FR/O=Bastion Academy/OU=Wazuh"
DAYS=825

if [[ -f "$OUT/ca/root-ca.pem" ]]; then
  echo "certificates already present, nothing to do"
  exit 0
fi

work=$(mktemp -d)
cd "$work"

# Private CA, valid only for this installation.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out root-ca.key
openssl req -x509 -new -key root-ca.key -sha256 -days "$DAYS" -subj "$SUBJ/CN=Bastion Wazuh local CA" -out root-ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# cert <name> <extendedKeyUsage>: PKCS#8 key (required by OpenSearch), SAN = the service name.
cert() {
  local name=$1 eku=$2
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$name.key"
  openssl req -new -key "$name.key" -subj "$SUBJ/CN=$name" -out "$name.csr"
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=%s\nsubjectAltName=DNS:%s\n' "$eku" "$name" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -sha256 -days "$DAYS" -extfile "$name.ext" -out "$name.pem"
}
cert wazuh.indexer serverAuth,clientAuth
cert wazuh.manager clientAuth
cert wazuh.dashboard serverAuth,clientAuth
cert admin clientAuth

# One directory per consumer, owned by the user that reads it; the CA key goes nowhere.
install -d -m 700 -o 1000 -g 1000 "$OUT/indexer" "$OUT/dashboard"
install -d -m 700 -o 999 -g 999 "$OUT/manager"
install -d -m 700 "$OUT/ca"
install -m 400 -o 1000 -g 1000 root-ca.pem wazuh.indexer.pem wazuh.indexer.key admin.pem admin.key "$OUT/indexer/"
install -m 400 -o 1000 -g 1000 root-ca.pem wazuh.dashboard.pem wazuh.dashboard.key "$OUT/dashboard/"
install -m 400 -o 999 -g 999 root-ca.pem wazuh.manager.pem wazuh.manager.key "$OUT/manager/"
install -m 400 root-ca.pem root-ca.key "$OUT/ca/"

rm -rf "$work"
echo "certificates created"
