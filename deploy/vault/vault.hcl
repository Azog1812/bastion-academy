# Vault server for the local stack (ADR 0019): docker compose -f docker-compose.yml -f docker-compose.vault.yml up -d
# One node, integrated storage (raft) on its own volume, reachable only on the internal
# `kms` network. TLS is off because nothing leaves that network (as for the lab runner);
# hosting needs TLS here and VAULT_ADDR=https://... (the platform refuses http across a network).
storage "raft" {
  path    = "/vault/file"
  node_id = "bastion-vault"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://vault:8200"
cluster_addr = "http://vault:8201"

# With integrated storage HashiCorp recommends disable_mlock; the container has no swap
# limit to rely on, but it runs without any capability (IPC_LOCK included).
disable_mlock = true
ui            = false
