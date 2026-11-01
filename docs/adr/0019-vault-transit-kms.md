# 0019 — Key Encryption Keys in Vault Transit

**Status:** accepted (1 Nov 2026). Extends ADR 0001 (envelope encryption); roadmap item
"External KMS for KEKs".

## Context
Notes and TOTP seeds are protected by envelope encryption (ADR 0001): a random DEK per
note, wrapped by a KEK from `ENCRYPTION_KEYS`. A database dump alone reveals nothing. But
the KEKs live in the platform's environment and memory: whoever gets the database *and*
the platform's secret file (a backup of the host, a container escape, a leaked `.env`)
decrypts everything, offline, with no trace. Rotation needs the operator to edit a secret
and redeploy, and nothing records who used a KEK.

A KMS changes the property that matters: the KEK never leaves it. The platform sends a
DEK to be wrapped or unwrapped and gets the result; a thief with the database and the
platform's files still needs a live, authorised call, which the KMS logs and the operator
can revoke. HashiCorp Vault's Transit engine is that KMS on-premises (OpenBao, its open
source fork, has the same API), and it maps to AWS KMS, GCP KMS or Azure Key Vault
hosted.

## Decision

### One interface, the call sites unchanged
`src/crypto/kms.ts` defines `Kms`: `wrap`, `unwrap` (batched), `rewrap`, `activeKeyId`.
`envelope.ts` keeps the same structure: the content is still AES-256-GCM under a per-note
DEK, bound to note id and owner id as associated data; only the wrapping of the DEK (and
of TOTP seeds) moves behind the interface. Implementations:
- `LocalKms`: the existing ring, **byte-compatible** with every row already written
  (same associated data `<context>:<keyId>`, same layout; a test builds a row the old way
  and opens it).
- `VaultTransitKms`: Transit over its HTTP API with node's `fetch`, no client library
  (invariant 11).
- `CompositeKms`: wraps with the active KMS, unwraps with whichever owns the key id. With
  `KMS_PROVIDER=vault` and the old ring still configured, existing rows keep opening, and
  `rotate-keys` moves them into Vault; then the ring is deleted from `.env`.

### Binding a DEK to its note, inside Vault
Locally the DEK's GCM associated data names its note, so a DEK copied into another row
fails. Transit offers two ways to do the same. `associated_data` works for encrypt and
decrypt, but the real Vault refuses it in `rewrap` (checked: "message authentication
failed"), so rotation would have to bring every DEK out to Bastion and back. A **derived
key** (`derived=true`, a key per `context`) binds just as well and works with `rewrap`:
rotation happens inside Vault, and no DEK ever comes out during it. The context is the
same string as the local associated data (`bastion:note-dek:v1:<noteId>`,
`bastion:totp-secret:v1:<userId>`).

### The key Bastion trusts, checked at boot
At start-up the platform reads the key's metadata and **refuses to start** unless it is
`aes256-gcm96`, derived, not exportable, without plaintext backup and not deletable
(fail closed, invariant 8). An exportable key would put every KEK one API call away; a
deletable one would make every note unreadable with one call.

### Least privilege, in Vault's own terms
`deploy/vault/bastion-policy.hcl` grants encrypt, decrypt and rewrap on one key, read of
its metadata, and `rotate` (a new version, operator CLI). Not granted, and checked against
the real Vault: export, backup, `config` (raising `min_decryption_version` would destroy
old rows), delete, and every other path.

### AppRole and short-lived tokens
Bastion logs in with AppRole (role id + secret id, files on a volume only it and the setup
job mount) and gets **1-hour tokens** (4 h at most), fetched again at two thirds of their
lease or after a 403. No long-lived token sits on disk; one login at a time even under
concurrent requests. A static `VAULT_TOKEN` is accepted for simple setups and tests.
Requests never follow redirects (the token would follow), never log or return Vault's
body, and time out after 5 s.

### An outage is not tampering
Two errors, kept apart: `DecryptionError` (a ciphertext that does not authenticate, a key
id that does not match its ciphertext: tampering, raises `BastionCiphertextTampering`) and
`KmsUnavailable` (sealed, unreachable, token refused: **503** with `Retry-After`, a
warning in the log, no alert of the tampering kind). Paging the security on-call because
Vault restarted would teach them to ignore that alert.

### Fewer round trips
A page of notes is opened with **one** Transit batch decrypt, not one call per note.

### The local Vault (docker-compose.vault.yml)
One node, integrated storage on its own volume, on an `internal` network with no published
port. `deploy/vault/init.sh` runs at every `up`: the first time it initialises (one key
share), enables the audit log (every request logged by Vault, secrets HMAC-ed), Transit,
the key, the policy and AppRole, writes Bastion's credentials (0400, its uid), and
**revokes the root token**; afterwards it only unseals. Both containers run without
capabilities (`CHOWN` only for the setup job), read-only root, no-new-privileges.

## Rejected options
- *A Vault client library* (node-vault): a dependency tree on the path of every DEK, for
  five HTTP calls (invariant 11).
- *`associated_data` instead of derived keys*: refused by `rewrap`, so rotation would
  expose every DEK to the platform.
- *A periodic token renewed by the platform*: dies if the stack stays off longer than its
  period, and is a long-lived secret on disk. AppRole re-logs in instead.
- *Vault dev mode*: in-memory, a known root token, everything lost at restart: every note
  unreadable after a reboot.
- *Making Vault the default*: the local install would need Vault to start at all. The
  overlay keeps it a deliberate choice; the code path is the same.

## Consequences
- `KMS_PROVIDER=vault` with `VAULT_ADDR` and either AppRole (`VAULT_ROLE_ID`,
  `VAULT_SECRET_ID`, `_FILE` preferred) or `VAULT_TOKEN`. Plain http only to a container
  name on a private network; https otherwise in production (config refuses).
- `rotate-keys` with Vault: a new key version, then every row re-wrapped by Vault. Old
  versions keep decrypting until an operator raises `min_decryption_version` (with an
  admin token, not Bastion's).
- The unseal key sits in a volume on the same host (accepted risk, threat model §5):
  hosting uses auto-unseal through a cloud KMS or an HSM.
- Note and MFA services became asynchronous; every place that reads a row then writes it
  after a KMS call keeps a compare-and-set (note `version`, TOTP `last_step` **and** the
  sealed seed, rotation on the old `wrapped_dek`), so the new `await` opens no race.
- Tests: `kms-vault.test.ts` against a Transit stand-in (context binding, key id and
  ciphertext disagreeing, sealed/down/revoked → 503 without the tampering alert, no
  redirect, unsafe keys refused, AppRole re-login, migration from the ring);
  `test/vault-real/run.sh` and the *Vault KMS* workflow prove it against the real Vault.
