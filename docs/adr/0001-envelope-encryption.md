# 0001 — Envelope encryption with per-record keys and AAD binding

**Status:** accepted

## Context
Notes are the asset users trust us with. Disk encryption alone protects against a
stolen disk, not against a leaked backup, a SQL injection or an over-privileged
operator reading the database. We also need to rotate keys without downtime.

## Decision
- Each note is encrypted with its own random 256-bit DEK, AES-256-GCM, 96-bit random IV.
- The DEK is wrapped with a KEK from a versioned key ring (`ENCRYPTION_KEYS`, `ACTIVE_KEY_ID`).
- AAD = note id + owner id for the content, note id + key id for the wrapped DEK.
- Rotation re-wraps DEKs only (`node dist/cli.js rotate-keys`).

## Alternatives rejected
- **One application-wide key:** rotation means re-encrypting everything; one IV collision risk across all data.
- **AES-CBC + HMAC:** correct if done right, but two primitives to get right instead of one AEAD.
- **SQLCipher (whole-DB encryption):** a native dependency, and an attacker with app-level access still reads everything.

## Consequences
- A DB dump alone is useless; row swapping / relocation is detected.
- Search over note contents is impossible server-side (accepted).
- KEK custody becomes the critical secret → mounted file from a secret manager; an external KMS (Vault Transit, cloud KMS) is the natural next step and only changes `wrapDek` / `unwrapDek`.
