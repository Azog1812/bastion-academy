# 0018 — Alert routing (Alertmanager) and dashboards (Grafana), as tested code

**Status:** accepted (1 Nov 2026). Completes ADR 0011, which left "Alertmanager routing,
Grafana dashboards" for later.

## Context
ADR 0011 made Prometheus decide *that* something is wrong: twelve rules, each unit-tested
with `promtool`. Nothing decided *who* hears about it. In the Prometheus UI a refresh token
replay (an incident on its own) sat next to a shared flag (a question for the trainers),
with nothing to say which one wakes someone up, and nothing to say when an alert is only
the symptom of another one. And nobody watches a list of rules: people read a dashboard.

The tools are the standard ones (Alertmanager, Grafana). The decisions are about who can
silence an alert, how to know the alerting itself still works, and how to keep routing
and dashboards from drifting away from what the platform really exports.

## Decision

### Routing by severity, in a tested tree
`deploy/alertmanager/alertmanager.yml`:

| Severity | Receiver | Timing | Why |
|---|---|---|---|
| `critical` (token replay, ciphertext tampering, Bastion down, pipeline broken) | `pager` | no grouping delay, repeated every hour | the first event is the incident |
| `warning` (stuffing, MFA guessing, probing, 5xx, export failing) | `secops` | grouped by alert name, 5 min | 50 failures from 50 addresses are one incident, one message |
| `info` (shared flag) | `trainers` | batched, once a day | a teaching matter, not a security page |
| `Watchdog` | `watchdog` | every 5 min | the dead man's switch, below |

An alert without a known severity falls to `secops`: a new rule someone forgot to label
still reaches a human. Every alert carries a severity from that set (unit test).

**Inhibition** removes symptoms, not causes: `BastionDown` mutes every warning and info
(their counters are stale while the target cannot be scraped); `BastionCredentialStuffing`
mutes `BastionAccountLockouts` (the lockouts are its consequence); `BastionEventLoopBlocked`
mutes `BastionHighErrorRate`. Critical alerts are never inhibited.

**Tested like the rules.** `deploy/alertmanager/routes.test.sh` runs `amtool check-config`,
then `amtool config routes test --verify.receivers` for every alert of `alerts.yml` with
its labels, then starts a real Alertmanager (loopback, random port), posts alerts to its
API and checks which come back inhibited, in two scenarios (up, then down). `amtool`
cannot test inhibition; the live instance can. CI runs it in the `alert-rules` job, with
the image pinned by digest as in Compose.

### A dead man's switch
`Watchdog` (`expr: vector(1)`) always fires. Its absence at the receiver is the only
signal that the pipeline itself is broken: a dead Prometheus fires nothing, including the
alert that would say it is dead. Two rules cover the parts Prometheus can see:
`AlertmanagerUnreachable` (no Alertmanager discovered for 5 minutes) and
`AlertmanagerNotificationsFailing` (a receiver refuses deliveries), both critical, both
with `promtool` tests. On a hosted install the watchdog receiver is an external
dead-man's-switch service (it alerts when the pings *stop*).

### Silencing is a privilege: Alertmanager publishes no port
Alertmanager has no authentication, and its API creates silences. Silencing the alerts is
an attacker's goal (MITRE ATT&CK T1562, Impair Defenses): one `POST /api/v2/silences`
with a regex matcher and every alert is muted for as long as the attacker likes. So
Alertmanager is only on the internal `metrics` network, with no published port, not even on
loopback: any local process, or a page in the browser doing DNS rebinding, could reach a
loopback port. People reach alerts and silences through Grafana, after logging in; a
silence carries its author and a comment. Prometheus' own UI stays on loopback as in
ADR 0011: it is read-only (no admin API, no lifecycle endpoint).

### Grafana: provisioned, logged in, quiet
- **Provisioned from git** (`deploy/grafana/provisioning`, `deploy/grafana/dashboards`,
  mounted read-only): data sources with fixed uids, the dashboard with
  `allowUiUpdates: false`. A dashboard edited in the UI would drift from what was reviewed.
- **Login required**: anonymous access, sign-up and org creation off; the admin password
  comes from `GRAFANA_ADMIN_PASSWORD` (new in `gen-secrets`) through a compose secret and
  `GF_SECURITY_ADMIN_PASSWORD__FILE`, never a plain variable (`docker inspect` shows
  variables). No `admin/admin` default survives (invariant 18). Cookies `SameSite=Strict`.
- **No phoning home**: telemetry, update checks, news feed, Gravatar, external snapshots
  and the plugin catalogue off; no plugin preinstalled.
- **One dashboard, *Bastion - overview***: headline numbers (alerts firing, request rate,
  5xx share, p95 latency, accounts, MFA adoption), the firing alerts with their runbook
  link, RED traffic, then one panel per security signal with its alert threshold drawn
  on it. One measure per panel (no second y-axis); series colours from a fixed order
  checked for colour-vision deficiency, status colours kept for thresholds.

### Names checked against the real exports
A PromQL query on a metric that does not exist returns nothing, forever, without an error:
an alert that never fires, a panel that always says "no data". `promtool` and `amtool`
check syntax, not that. `test/unit/observability-config.test.ts` scrapes the real
registry and checks that every metric in `alerts.yml` and in the dashboard is exported,
that every `action`/`outcome` filter belongs to the closed lists (`AUDIT_ACTIONS`), that
every alert links to a runbook section that exists, and that every panel uses a
provisioned data source.

## Rejected options
- *Publishing Alertmanager on loopback, as Prometheus*: simplest, but leaves silences to
  any local process. Basic auth (`--web.config.file`) needs a bcrypt hash generated at setup
  with a tool the stack does not have (no dependency, invariant 11); routing access
  through Grafana's login gets the same result with nothing to install.
- *Grafana-managed alert rules*: they would move alerts out of `promtool`-tested files
  into Grafana's database, edited by clicks.
- *Shipping e-mail or chat integrations*: a local install has no mail server and no chat,
  and the person on call is the learner. Receivers are ready for them; credentials go in
  `*_file` fields pointing at secrets, never in the YAML that is in git.
- *A Grafana image renderer, Loki, tracing*: more containers and memory for a local
  learning platform; the audit log already goes to Wazuh (ADR 0015).

## Consequences
- `docker compose --profile observability up -d` now also starts Alertmanager (128 MiB, no
  port) and Grafana on `127.0.0.1:3001` (512 MiB). An old `.env` needs
  `GRAFANA_ADMIN_PASSWORD`.
- Grafana is not `read_only` (an environment-sourced secret is copied into the container,
  as for Prometheus); it runs as uid 472 without capabilities.
- Grafana's edge network gives it a route out (needed to publish the port); everything
  that would use it is turned off.
- Checked on the real stack: both targets up, Prometheus discovers Alertmanager, the
  watchdog reaches its receiver through Grafana's proxy, Alertmanager unreachable from the
  host, Grafana 401 without login and with `admin/admin`, every dashboard query valid.
