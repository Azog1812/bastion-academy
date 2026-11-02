# 0021 — PostgreSQL as a second database engine

**Status:** accepted (2 Nov 2026). Second step of the roadmap item "PostgreSQL + Redis",
after the asynchronous layer of ADR 0020. Row-level security and the shared rate-limit
store follow in their own changes.

## Context
SQLite is one file on one host: one replica of the platform, no more. Hosting several
replicas behind a load balancer needs a database they all reach. ADR 0020 already put
every query behind an asynchronous `Db` interface and made every check-then-act atomic in
the database. What is left is the engine itself, and the races a real concurrent
database adds: SQLite serialises transactions on its single connection, PostgreSQL runs
them side by side.

## Decision

### Two engines, one SQL
SQLite stays the default: `npm start` and the local Docker install keep working with no
server to run, and the test suite stays fast. `DATABASE_URL` switches to PostgreSQL
(`src/postgres.ts`); `docker-compose.postgres.yml` adds a server on an internal network.
Services write one SQL, the subset both engines run the same way, with `?` placeholders.
Three queries had to change for that: `IS ?` became `IS NOT DISTINCT FROM ?`, the scalar
`MAX(a, b)` (SQLite only) a `CASE`, and an upsert names its table. The adapter numbers the
placeholders (`$1, $2…`, outside quoted text only, and refuses a `$` in service SQL), and
returns rows of the same shape: BIGINT and COUNT as numbers (refusing one a JavaScript
number would round), BYTEA as a plain `Uint8Array`.

### Client: `pg`, pure JavaScript
The PostgreSQL wire protocol (SCRAM, TLS, extended query protocol, type parsing) is too
much to hand-roll safely; `pg` is the reference client. Only its pure-JavaScript code runs:
`pg-native`, which compiles libpq, is an optional peer dependency and is never installed,
and no package in the tree has an install script (invariant 11). It brings 13 small
packages, mostly by the same maintainer; Dependabot, `npm audit signatures` and
OSV-Scanner watch them like the rest.

### Transactions: SERIALIZABLE, retried
Every transaction runs at `SERIALIZABLE`: PostgreSQL aborts one of two transactions that
would not give the same result run one after the other (error 40001), and the adapter runs
it again from the start, up to five times with a jittered backoff. So "count the passkeys,
insert if under the cap" stays correct with no `SELECT … FOR UPDATE` in the services, the
same code as on SQLite. The price: a transaction body may run more than once, so it only
touches the database (no KMS call, no audit record inside), which `Db.transaction`
documents and every existing body already respected.

### The audit chain: an advisory lock
Each audit entry links to the previous one, so appends all read the same row, the chain
head. Under SERIALIZABLE alone the chain stays correct, but concurrent appends abort each
other: with a pool of 20 connections, 82 of 300 concurrent appends ran out of retries, each
a lost security event and a failed request. Audit appends therefore take
`pg_advisory_xact_lock` and queue: none fails, in the same total time. They run at
`READ COMMITTED`, not `SERIALIZABLE`: a serializable snapshot is taken by the first
statement, the lock itself, before the wait, and the head read after the wait would be
stale. The lock set is closed (`audit_log`, plus one for migrations).

### Schema
One migration creates the schema of SQLite's seven, translated: BIGINT for millisecond
timestamps (they overflow INTEGER), BYTEA for ciphertext and keys, an identity column for
the audit sequence, and the append-only triggers, which also refuse `TRUNCATE` (it skips
row triggers). E-mails and pseudonyms compare without case through an ICU collation;
SQLite's NOCASE folds ASCII only, the collation all of Unicode, which is stricter for
pseudonyms ("Ädmin" and "ädmin" cannot coexist). Replicas booting together wait on an
advisory lock; the first one migrates, inside one transaction.

### The link
The database receives password hashes, sealed TOTP seeds and wrapped DEKs, and the URL
holds its password: `DATABASE_URL` can come from a file (`DATABASE_URL_FILE`), and in
production the configuration refuses a server across a network without
`sslmode=verify-full` (`require` encrypts but does not check whose certificate it is).
Plain connections stay allowed where no network is crossed: loopback, or a container name
on a private Docker network, as for Vault (ADR 0019). Statements time out after 5 s and
an idle transaction after 10 s, so a bug cannot hold locks for ever.

### Both engines are tested
A CI job runs the whole suite again against PostgreSQL 18 (same image and digest as the
compose file), each test context in a schema of its own. It found what SQLite had hidden:
the lockout counter and the lock it sets were two statements, and guesses landing between
them were counted on top of the threshold, each one a guess with a verdict. Counting and
locking are now one transaction, the reset after a right password a compare-and-set on
the lock, and the race test runs against `withLatency()`, where it failed before the fix
on SQLite too.

## Consequences
- Several replicas can share one database. Rate limits are still kept per replica, in
  memory, so N replicas allow N times the configured attempts per address until the Redis
  store (next change): accepted until then (threat model §5).
- Audit appends are serialised across replicas: a throughput limit by design, since the
  chain has one head.
- `DROP TRIGGER` differs between the engines; tests that play the attacker go through a
  helper (`dropAuditTrigger`) and `Db.dialect`, the only place code asks which engine runs.
- The schema now exists twice (`db.ts`, `postgres.ts`): a new table or column goes into
  both, and the PostgreSQL CI job fails if the second is forgotten.
- Data is not migrated from SQLite to PostgreSQL: the switch starts from an empty
  database (local installs hold training progress, not production data).

## Alternatives considered
- *PostgreSQL only:* simpler code, but every local install and every test run would need
  a server; the local "clone and start" experience is part of the product.
- *An ORM or query builder (Knex, Drizzle, Prisma) to hide the dialects:* more dependencies
  (Prisma ships a native engine), and invariant 1 is easier to prove on plain bound SQL.
- *`SELECT … FOR UPDATE` in the services instead of SERIALIZABLE:* dialect-specific, does
  not lock rows that do not exist yet (the count-then-insert caps), and easy to forget in
  one place.
- *`postgres` (porsager) instead of `pg`:* zero dependencies, but tagged-template queries
  would have meant a second query style next to `?`, and the lint rules that ban SQL
  templates (invariant 1) would have had to tell the two apart.
