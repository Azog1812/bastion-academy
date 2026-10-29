# 0002 — SQLite via the built-in driver, single replica

**Status:** accepted

## Context
The project needs real persistence, transactions and constraints, with the smallest
possible supply-chain and operational footprint.

## Decision
Use `node:sqlite` (built into Node ≥ 22.5): no native addon to compile, no install
scripts, nothing downloaded at install time. `STRICT` tables, foreign keys, WAL,
`secure_delete`, `trusted_schema = OFF`. One replica, `Recreate` strategy.

## Consequences
- Zero native dependencies → `npm ci --ignore-scripts` works and the image stays distroless.
- `node:sqlite` is still flagged experimental by Node; the warning is silenced, the API is covered by tests.
- No horizontal scaling. The data-access layer is small and SQL-standard, so moving to
  PostgreSQL (and a Redis store for rate limits) is a contained change.
