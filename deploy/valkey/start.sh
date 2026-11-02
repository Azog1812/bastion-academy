#!/bin/sh
# Valkey for Bastion's shared rate limits (ADR 0023). Writes the ACL to a tmpfs and starts
# the server with it, so the password never appears on a command line (ps, /proc/*/cmdline):
# only its SHA-256 goes into the ACL file.
#  - `default` is off: no anonymous access, ever.
#  - `bastion` reaches its own keys (bastion:rl:*) and runs EVAL with exactly the commands
#    the rate-limit scripts use; nothing else (no CONFIG, KEYS, FLUSHALL, MODULE, DEBUG…),
#    and the ACL is checked again for every command a script calls.
set -eu
: "${VALKEY_PASSWORD:?VALKEY_PASSWORD is missing}"
umask 077
hash="$(printf '%s' "$VALKEY_PASSWORD" | sha256sum | cut -d' ' -f1)"
unset VALKEY_PASSWORD
cat > /run/valkey/users.acl <<EOF
user default off
user bastion on #$hash resetkeys ~bastion:rl:* resetchannels -@all +eval +del +ping +incr +pexpire +pttl +exists +get +decr
EOF
# Counters are worth nothing after a restart (a fresh window): no persistence. noeviction:
# a full memory refuses new counters (auth then fails closed) rather than silently evicting
# a counter, which would reset somebody's limit.
exec valkey-server --aclfile /run/valkey/users.acl --save '' --appendonly no \
  --maxmemory 64mb --maxmemory-policy noeviction --protected-mode yes --bind 0.0.0.0
