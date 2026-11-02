# 0023 — Shared rate limits in Redis/Valkey, and several replicas

**Status:** accepted (2 Nov 2026). Last step of the roadmap item "PostgreSQL + Redis", after
ADR 0020 (async layer), 0021 (PostgreSQL) and 0022 (row-level security).

## Context
Rate limits are Bastion's first answer to online guessing: 10 authentication requests per
address per 15 minutes, per-account budgets for flags, quizzes, labs and detection rules,
and a global flood guard. `express-rate-limit` counts in memory, per process. With
PostgreSQL, several replicas can now share one database, and each would keep its own
counters: N replicas allow N times every limit (ADR 0021 accepted it until this change).
The account lockout is not affected: it lives in the database.

## Decision

### One counter per client, in Redis
`REDIS_URL` gives every limiter a store in Redis (`src/http/rate-limit-store.ts`). The
increment is one Lua script, `INCR` then `PEXPIRE` on the first hit, atomic on the server:
two replicas counting the same client never both see a first hit, and a key can never be
left without an expiry (which would be a permanent ban). Keys are
`bastion:rl:<limiter>:<SHA-256 of the client key>`: no IP address or user id in clear in
Redis, and every key the same bounded length. The concurrency test was checked to fail
with a read-then-write implementation (24 requests through instead of 10).

### An in-house RESP client
The rate limits need AUTH, EVAL, DEL and PING. `node-redis` or `ioredis` would bring a
dependency tree for that; `src/redis.ts` speaks RESP2 on `node:net`/`node:tls` in under
300 lines (invariant 11). Commands are arrays of length-prefixed bulk strings, so no
argument can inject a second command. Replies are parsed with hard bounds (512 KiB per
string, 1024 items per array, depth 4, 2 MiB buffered), RESP3 types are refused, a reply
nobody asked for drops the connection, and a slow reply breaks it (pipelined replies would
otherwise be matched to the wrong command). After a failure, commands fail fast for a
second instead of reconnecting at every request. `rediss://` verifies the certificate;
production refuses plain `redis://` across a network (same rule as PostgreSQL and Vault).

### When Redis is down: closed for guessing, open for the flood guard
The limiters that stop guessing (auth, refresh, flags, quizzes, labs, detection) fail
**closed**: 503, generic message. Letting logins through unlimited during an outage would
be a brute-force window anyone can open by attacking Redis. The global flood guard fails
**open**: refusing every request would turn a Redis outage into a full outage. Readiness
does not depend on Redis for the same reason (pulling every replica would be worse).
Every store failure is counted (`bastion_rate_limit_store_errors_total{limiter}`) and
alerts (`BastionRateLimitStoreDown`, promtool-tested, routed, runbook section); the log
line is throttled to one per limiter every 10 s.

### Valkey, least privilege
The compose overlay runs Valkey (the BSD-licensed fork of Redis, same protocol):
- `default` user off, so no anonymous access.
- User `bastion` limited to keys `bastion:rl:*`, and to `EVAL` plus exactly the commands
  the scripts call. The ACL is checked again for each command inside a script, so
  `FLUSHALL` from Lua is refused too.
- The ACL file is written to a tmpfs by `deploy/valkey/start.sh`, with the password's
  SHA-256 only, never on a command line.
- No persistence: after a restart every client starts a fresh window, accepted.
- `noeviction`: a full memory refuses new counters (auth then fails closed) rather than
  evicting someone's counter, which would reset their limit.
- Non-root, read-only, no capability, no published port, its own `internal` network.

### Several replicas behind a load balancer
`docker-compose.replicas.yml` runs two API replicas behind nginx (unprivileged image), the
only published port (loopback). The API trusts exactly one proxy hop, so nginx
**overwrites** `X-Forwarded-For` with the address it sees: appending would let a client
choose the address the limits count. Checked on the running stack: 14 logins, each with a
different forged `X-Forwarded-For`, spread over both replicas, the 11th refused. nginx
forwards `Host` with its port (`$http_host`): the browser-session routes compare `Origin`
with it (ADR 0007), and the first configuration, with the port dropped, would have refused
every browser login behind the load balancer. Prometheus
discovers every replica through DNS instead of one static target.

## Consequences
- Limits hold across replicas: one budget per client however many replicas run.
- Redis becomes a dependency of logging in. An outage refuses logins (503), alerted, rather
  than opening a brute-force window.
- One more secret (`REDIS_PASSWORD`) and one more service in the replicas overlay; the
  single-replica setup is unchanged (memory store, no Redis needed).
- The lab reaper runs in every replica, so two can find the same expired lab. A test
  against `withLatency()` showed both stopping it and both auditing `lab.expire`; the delete
  is now a compare-and-set, and only the replica that removed the row goes on (stopping at
  the runner was already idempotent). Lab starts were already safe (UNIQUE slot per learner).
- The SIEM export appends whole JSON lines to one file from several writers; `seq` still
  orders them (ADR 0015).

## Alternatives considered
- *`rate-limit-redis` + `ioredis`:* the usual pair, but two packages and their tree for four
  commands, and less control over what a hostile reply can cost.
- *Counters in PostgreSQL:* no new service, but a write per request on the database every
  replica depends on, and expiry needs a sweeper; Redis TTLs are built for it.
- *Sticky sessions at the load balancer:* the limits would still be per replica for any
  client that changes replica (or is made to), and an attacker controls that.
- *Fail open everywhere:* availability first, but an attacker who can disturb Redis gets
  unlimited password guesses; the lockout would remain, the per-address limit would not.
