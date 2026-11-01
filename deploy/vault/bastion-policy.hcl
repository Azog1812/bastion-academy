# What the platform may do with Vault (ADR 0019): use one Transit key, nothing else.
# It can wrap, unwrap and re-wrap DEKs, read the key's metadata (boot check) and add a new
# version (operator CLI rotate-keys). It cannot export, back up, delete or reconfigure the
# key (min_decryption_version would make old rows unreadable), nor touch any other path.
path "transit/encrypt/bastion-kek" {
  capabilities = ["update"]
}
path "transit/decrypt/bastion-kek" {
  capabilities = ["update"]
}
path "transit/rewrap/bastion-kek" {
  capabilities = ["update"]
}
path "transit/keys/bastion-kek" {
  capabilities = ["read"]
}
path "transit/keys/bastion-kek/rotate" {
  capabilities = ["update"]
}
