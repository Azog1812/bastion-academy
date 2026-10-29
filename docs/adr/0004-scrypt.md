# 0004 — scrypt for password hashing

**Status:** accepted

## Context
OWASP's recommended order is Argon2id, then scrypt, then bcrypt. Argon2 in Node needs a
native addon (`argon2` package: compiled code, install scripts, prebuilt binaries
downloaded at install time).

## Decision
scrypt from `node:crypto` with OWASP parameters N=2¹⁷, r=8, p=1, 64-byte output, 16-byte
salt, self-describing hash format, transparent rehash when the cost factor is raised.

## Consequences
- Memory-hard and OWASP-compliant with zero native dependencies.
- 128 MiB per hash: concurrency is bounded by the libuv pool (`UV_THREADPOOL_SIZE=4`) and
  the container memory limit is sized accordingly (768 MiB).
- Production refuses to start with N < 2¹⁷; tests use 2¹⁰ for speed.
