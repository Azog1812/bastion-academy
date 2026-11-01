# 0011 — Observability: Prometheus metrics and tested alerts

**Status:** accepted (v6, 31 Oct 2026)

## Context
Bastion records every security-relevant event in a tamper-evident audit log
(invariant 10), and the runbook says what to do when a token is replayed or a
ciphertext fails authentication. But nobody reads an audit table in real time: an
event that nobody is alerted to is only useful after the breach. Operations need
numbers (is the API up, is it slow, are errors climbing) and security needs alerts
(a password spray, a stolen refresh token) that reach a human in minutes.

## Decision

### Metrics, Prometheus format, no dependency
`src/metrics.ts` writes the Prometheus text exposition format (counters, histograms,
gauges read at scrape time) on `node:` built-ins. `prom-client` was rejected: the
format is a few lines of text, stable for years, and fully tested here; a dependency
would add supply-chain surface for no capability (invariant 11).

| Metric | Source | Why |
|---|---|---|
| `bastion_audit_events_total{action,outcome}` | a hook in `AuditLog.record` | every audited event becomes countable from the one place that sees them all; a new audited action is measured with no extra code |
| `bastion_integrity_failures_total` | the error handler, on `DecryptionError` | database tampering (ADR 0001) |
| `http_requests_total{method,route,status}`, `http_request_duration_seconds` | a middleware | availability, errors, latency (RED method) |
| `bastion_users`, `bastion_mfa_enabled_users`, `bastion_labs_active` | `COUNT(*)` at scrape time | capacity, MFA adoption; never stale, nothing stored |
| `process_*`, `nodejs_*`, `bastion_build_info` | runtime | memory, a blocked event loop |

### Labels come from closed sets only
A label fed by the request is two vulnerabilities at once: a **privacy leak** (an
e-mail or IP copied into a monitoring system with its own retention and its own
readers) and a **memory DoS** (every distinct value allocates a series, forever).
So labels are route *patterns* (`/v1/notes/:id`, never the URL), audit actions (a
closed union), status codes and a fixed list of methods. Requests no route matched
share `route="none"`. A per-metric cap (`MAX_SERIES`) drops new series beyond 1,000
and counts the drops (`bastion_metrics_series_dropped_total`, alerted): it is the
backstop if the rule is ever broken, not the control.

### A separate listener, behind a token
Metrics are served by a second HTTP listener on `METRICS_PORT`, never by the API:
- the published port and the ingress only reach the API, so `/metrics` cannot end
  up on the Internet through a wrong proxy rule;
- in Compose the port is only on an `internal` network shared with Prometheus; in
  Kubernetes it is absent from the Service and a NetworkPolicy admits only
  Prometheus pods from the `monitoring` namespace;
- the scrape needs `Authorization: Bearer <METRICS_TOKEN>` (compared as SHA-256
  digests with `timingSafeEqual`). Metrics are sensitive: they reveal the number of
  accounts and, worse, **whether an attack is being noticed**, which tells an
  attacker how slow to go. Prometheus reads the token from a file
  (`credentials_file`), like the platform reads its secrets.

Metrics are off unless `METRICS_PORT` is set, and the configuration refuses to start
with a port but no token, or with the API's own port (fail closed, invariant 8).

### Alerts are code, and code is tested
`deploy/prometheus/alerts.yml` holds eleven alerts, each pointing to its runbook
section: refresh token replay and ciphertext tampering (critical, first event),
credential stuffing, lockouts, MFA guessing, authorization probing, shared flags,
target down, 5xx rate, blocked event loop, series cap reached.
`deploy/prometheus/alerts.test.yml` feeds synthetic series to `promtool test rules`:
each alert must fire on the attack it is written for, at the expected time, and stay
quiet on normal traffic (a few typos a minute do not page anyone). CI runs it with the
same pinned image as Compose.

### Counters start at zero
A labelled series that appears directly at 1 has no earlier sample, so
`increase()` sees no increase and the alert never fires: exactly the first, most
important, refresh token replay. The end-to-end test against the real stack caught
it (the `promtool` tests, which start their series at 0, could not). Every
action × outcome pair, and every label-less counter, is exported at 0 from start-up.

## Consequences
- Security events now page someone; the runbook and the alerts share their names.
- New optional secret `METRICS_TOKEN` (from `cli gen-secrets`). The Compose stack
  requires it in `.env`, so an old `.env` fails with a clear message.
- `docker compose --profile observability up -d` adds Prometheus on
  `127.0.0.1:9090`, with a 7-day retention. Its root filesystem is not read-only:
  Compose copies an environment-sourced secret into the container, which a
  read-only root refuses. It runs as `nobody` without capabilities, so little is lost.
- Alertmanager routing and Grafana dashboards: ADR 0018. Not done: tracing.
  Counters live in memory: they restart at 0 with the process, which Prometheus'
  `increase()` handles as a counter reset.
- Learners do not see these metrics; a lesson on monitoring and a Wazuh module are the
  pedagogical side, planned next.
