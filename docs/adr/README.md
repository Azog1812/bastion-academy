# Architecture Decision Records

Short records of *why* things are the way they are, including the options rejected.
Format: context → decision → consequences.

| # | Decision |
|---|---|
| [0001](0001-envelope-encryption.md) | Envelope encryption with per-record keys and AAD binding |
| [0002](0002-sqlite-single-replica.md) | SQLite (built-in driver), single replica |
| [0003](0003-short-jwt-plus-rotating-refresh.md) | Short-lived JWT + opaque rotating refresh tokens, revocable |
| [0004](0004-scrypt.md) | scrypt for password hashing |
| [0005](0005-distroless-signed-images.md) | Distroless runtime, signed images, admission control |
