# 0020 — An asynchronous database layer, and transactions as the unit of atomicity

**Status:** accepted (2 Nov 2026). First step of the roadmap item "PostgreSQL + Redis";
the PostgreSQL backend, row-level security and the shared rate-limit store follow in
their own changes.

## Context
Every service called `node:sqlite` directly: `db.prepare(sql).get(...)`, synchronous.
Several security properties rested on that, often without saying so. Node runs one thing
at a time, and a synchronous call cannot be interrupted, so a read followed by a write
with no `await` in between was atomic *by accident of the driver*:
- the HMAC-chained audit log read the chain head, then inserted the next entry;
- removing a passkey counted the account's remaining factors, then deleted;
- enrolling a passkey counted against `MAX_PASSKEYS`, then inserted; the passwordless
  login challenges were capped the same way;
- the first recovery codes of an account were issued after checking there were none.

A network database (PostgreSQL, the next step) only has an asynchronous client. Every
query becomes an `await`, and every one of those sequences becomes a race: two requests
interleave between the read and the write. Two of them are security bugs, not just
untidiness: two concurrent appends read the same chain head and **fork the audit chain**
(`verify()` then reports the honest log as tampered), and two concurrent deletions of an
account's two passkeys each see "another factor remains" and leave the account with
**no second factor, no code ever asked** (invariant 14).

## Decision

### One asynchronous interface
`src/db.ts` exports `Db`: `one`, `many`, `run` (with `changes`), `transaction(fn)`,
`close`. Services and tests use nothing else; the SQLite driver stays private to
`db.ts`. Rows come back as `unknown` and the caller states the shape it selected, as
before. SQL keeps bound parameters (`?`) only; the ESLint rule and the Semgrep rules now
watch `one`/`many`/`run` (first argument) instead of `prepare`/`exec`, so invariants 1, 2
and 12 are still enforced, not just still true.

### Atomicity comes from the database, never from the event loop
A check-then-act is either **one statement** (compare-and-set: `UPDATE … WHERE
revoked_at IS NULL`, `… AND last_step < ?`, `INSERT … ON CONFLICT DO NOTHING`, a
`UNIQUE` constraint) or it runs **inside `transaction()`**. The sequences above now run in
a transaction; those that were already single statements (refresh-token claim, TOTP step,
passkey counter, MFA attempt cap, lab slot) are unchanged and their comments no longer
say "before any await". With PostgreSQL, transactions will run at `SERIALIZABLE` with a
retry on serialization failure, so the same service code stays correct without
dialect-specific `SELECT … FOR UPDATE`.

### SQLite: one connection, so transactions are serialised
SQLite has one connection per process. If a transaction awaited something (a KMS call)
between `BEGIN` and `COMMIT`, another request's statements would run *inside* it, and be
committed or rolled back with it. So while a transaction is open, every other operation
waits for it to end. The check "is a transaction open?" and the operation it guards run
in the same synchronous stretch: an earlier version awaited between the two, and a test
caught a second transaction slipping into the gap. Using the outer handle inside a
transaction throws (it would otherwise wait for itself forever), and a transaction handle
kept after the transaction ended throws too.

### Races are tested, against a database that behaves like a remote one
In-process SQLite answers within the same turn of the event loop, so a race test against
it passes whether or not the code is safe. `withLatency(db)` in `test/helpers.ts` yields to
the event loop before every query, as a network database would; race tests start the
competing calls in the same tick against it. Each was checked to **fail with the
protection removed**: without the audit transaction the chain forks after one entry,
without the passkey transaction both deletions succeed, without the serialisation a
rollback takes another request's write with it.

## Consequences
- Every service method that touches the database is `async`; Express 5 routes already
  were. The conversion found its own bugs: a `.map(async …)` that would have sent
  `[{}, {}, …]` as the challenge list, and an `expect(JSON.stringify(promise))` that
  would have made the "temporary password never reaches the audit log" test pass on
  `"{}"`; both fixed, the first caught by the test suite, the second by review.
- Prometheus gauges read the database at scrape time, so a scrape is asynchronous.
- The SIEM copy (ADR 0015) is written after the entry commits: under concurrent requests
  two lines can leave in a different order than `seq`; `seq` still orders them and still
  shows a gap.
- `audit.verify()` reads the chain in pages of 1000: memory stays bounded however long
  the log grows.
- SQLite serialises transactions, a throughput limit on a single replica, where SQLite is
  only meant for local use anyway; PostgreSQL removes it.

## Alternatives considered
- *Keep `node:sqlite` synchronous and add PostgreSQL through a worker thread with
  `Atomics.wait`:* keeps the old code, but every query would block the event loop for a
  network round trip, and the accidental atomicity would still be accidental.
- *Per-statement locking in the services (`SELECT … FOR UPDATE`):* not portable to
  SQLite, and easy to forget in one place; a transaction plus `SERIALIZABLE` covers every
  sequence the same way.
- *An ORM or query builder:* hides SQL (invariant 1 is easier to prove on plain bound
  SQL) and adds dependencies (invariant 11) for no security gain.
