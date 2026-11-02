# 0022 — Row-level security on notes, and an API login that cannot escape it

**Status:** accepted (2 Nov 2026). Third step of the roadmap item "PostgreSQL + Redis",
after ADR 0020 (async layer) and ADR 0021 (PostgreSQL). PostgreSQL only: SQLite has no
row-level security.

## Context
IDOR is the first risk of the OWASP API Top 10, and Bastion's main defence against it is
invariant 2: every note query carries `owner_id` in the SQL itself, checked by a Semgrep
rule and by tests that replay the attack with two accounts. That is one barrier, in the
application. A rule recognises shapes of queries; a bug that does not look like one (a
join, a new helper, a query built for a report) can still forget the owner. With
PostgreSQL, the database can hold a second barrier that does not depend on the code being
right.

## Decision

### A policy on `notes`
`notes` has row-level security enabled and one policy for the API's role:
`owner_id = current_setting('app.user_id', true)`, for reads (`USING`) and writes
(`WITH CHECK`). The note service runs every note query in a transaction that sets
`app.user_id` to the authenticated user (`transaction(fn, { user })`), so a query that
forgot its `owner_id` sees only that user's rows, and cannot write a row in someone else's
name. The `owner_id` stays in every query all the same: the policy is the second barrier,
not the first (and SQLite only has the first).

The setting is transaction-local (`set_config(…, true)`), never set on the connection: a
pooled connection that served Alice carries nothing into the next request. Without it,
the policy matches no row: a forgotten context fails closed (sees nothing, writes nothing).

### The API logs in as a role the policy binds
The table owner skips row-level security, and so do superusers and `BYPASSRLS` roles.
Migration v2 creates `bastion_app`: it owns nothing, cannot bypass RLS, can read and write
rows but not change the schema, and has only `SELECT` and `INSERT` on `audit_log` (it can
neither edit the log nor drop the triggers that protect it). The API logs in **as**
`bastion_app` (`DATABASE_URL`); migrations and the operator CLI use the owner
(`DATABASE_OWNER_URL`), in compose a one-shot `bastion-migrate` job.

The first version logged in as the owner and switched with the `role` connection
parameter. The abuse test `SET ROLE postgres` passed: PostgreSQL checks `SET ROLE`
against the login user, so injected SQL could switch back to the owner and every policy
was gone. Hence two logins, and a boot check: the API refuses to start if its role is a
superuser, has `BYPASSRLS`, owns the tables or is a member of the owner's role, or if the
schema is behind (fail closed, like the configuration).

### Probes are still detected
The note service tells a probe of someone else's note from a typo, for the audit log
(`authz.denied`, alert `BastionAuthorizationProbing`). Under the policy the API cannot see
that row any more, so it asks `note_exists(id)`, a `SECURITY DEFINER` function owned by
the schema owner that answers yes or no and nothing else, with its search path fixed at
creation (a function running as the owner must not resolve names through a path the
caller controls). Execution is revoked from `PUBLIC` and granted to `bastion_app` only.

## Consequences
- An IDOR bug that forgets `owner_id` on notes leaks nothing on PostgreSQL; on SQLite the
  application barrier remains the only one, as before.
- Every note operation is a transaction (BEGIN, the setting, the query, COMMIT): a few
  more round trips per request, which the abuse resistance is worth.
- Operator tasks spanning all owners (key rotation) run through the CLI as the owner;
  through the API's role row-level security would show them nothing.
- Two database passwords. In the single-host compose overlay `.env` reaches the API
  container whole, so code execution there would also read the owner's; an orchestrator
  gives the migration job and the API separate secrets (accepted, threat model §5).
- `bastion_app` is one role per PostgreSQL cluster, granted per schema.
- Tests: `t.db` is the owner (the attacker with database access, the administrator),
  `t.appDb` what the API uses; the row-level security tests run in the PostgreSQL CI job
  and were checked to fail with the policy disabled.

## Scope, and what is next
Notes only, the asset invariant 2 protects. Other per-user tables are read before a user
is known (refresh tokens by hash, passkeys by user handle during passwordless login) or
across users on purpose (the scoreboard), so a policy there needs its own design rather
than the same one-liner. Candidates: `lesson_progress`, `module_choices`, `user_mfa`.

## Alternatives considered
- *Owner login + `SET ROLE` per connection:* one password, but escapable by injected SQL
  (above), so it would only have protected against bugs, not against injection.
- *`FORCE ROW LEVEL SECURITY` on the owner:* the owner can still `ALTER TABLE … NO FORCE`
  or drop the policy; a role that owns nothing cannot.
- *Views per user, or `security_barrier` views:* more objects to keep in sync with every
  query, and nothing a policy does not already give.
