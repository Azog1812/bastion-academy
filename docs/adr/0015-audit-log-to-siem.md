# 0015 — Bastion's audit log, watched by the real Wazuh

**Status:** accepted (31 Oct 2026)

## Context
Bastion keeps a tamper-evident audit log (HMAC chain, append-only triggers) and counts
its events in Prometheus (ADR 0011). Counting is not investigating: an analyst needs the
events themselves, correlated, in the SIEM the learners are trained on. The Wazuh stack
already runs next to the platform (ADR 0013), and the Wazuh challenges teach how to write
rules for exactly this log (ADR 0014). The platform should practise what it teaches.

## Decision
- **A copy, not a second record.** When `AUDIT_EXPORT_FILE` is set, every audit entry is
  also appended as one JSON line to that file, from `AuditLog`'s single hook (the same
  one that feeds metrics). The database stays the record: chained, append-only, and the
  source for `verify-audit`. Each line carries the database `seq`, so a lost line shows as
  a gap in Wazuh.
- **One flat JSON object per line** (`ts`, `service: "bastion"`, `seq`, `action`,
  `outcome`, `actor`, `target`, `srcip`, then the details). Wazuh reads it with
  `log_format json`: no decoder to write, no regular expression. `action` and `srcip` land
  in Wazuh's static fields, the rest in dynamic ones. Details never overwrite the line's
  own keys.
- **No log injection (CWE-117).** `JSON.stringify` escapes every control character: a
  newline in a URL or an e-mail cannot start a forged line. Tested, and replayed in the
  real `wazuh-logtest`.
- **Its own volume, read-only for Wazuh.** The file lives in `bastion-audit`, mounted
  read-write in the platform and read-only in the manager; the SIEM never sees the
  database. The file is mode 0600 (it holds user ids and IP addresses) and owned by the
  app user; the manager's logcollector runs as root and reads it.
- **Failure does not stop the platform.** A write that fails is logged and counted
  (`bastion_audit_export_failures_total`, alert `BastionAuditExportFailing`); an
  unopenable path stops the boot (fail closed on configuration). Writes are synchronous,
  like the database insert, so lines keep the chain's order. Rotation by size keeps one
  previous file; a failed rotation keeps appending rather than dropping lines.
- **Production rules in the repository** (`deploy/wazuh/bastion_rules.xml`, ids
  100200-100299), copied into the manager at start: stolen refresh token (12), broken
  audit chain (15), access denied (10), lockout (10), shared flag (10), operator actions
  (8), weakened second factor (7), and failed logins correlated two ways (below).
- **Checked against the real engine.** CI (`wazuh.yml`) replays lines produced by the real
  `AuditLog` and export through `wazuh-logtest`: each line must end on its expected rule.
  `test/wazuh-real/end-to-end.sh` runs the whole chain with real containers (platform →
  volume → manager → `alerts.json`); too heavy for CI, run by hand.

## Two findings that changed the rules
- **Detection must fire below the preventive control.** The first version alerted on 10
  failed logins from one address in 5 minutes. The end-to-end test (platform container →
  file → manager → `alerts.json`) never fired it: Bastion's auth rate limit answers 429
  before a 10th request from one address, and a refused request is not audited. The rule
  now fires on 6 failures in 15 minutes from one address, and a second one on 50 failures
  in 5 minutes from any addresses, which the per-address limit cannot see (like the
  Prometheus alert `BastionCredentialStuffing`).
- **Wazuh uses up the events a correlation counted.** After the per-address rule fired on
  6 failures, the global rule on the same parent needed 50 *other* failures. The
  challenge evaluator now models it (ADR 0014).
- **The live manager is not exact at the threshold.** `wazuh-logtest` fires
  `frequency="6"` on the 6th event, every time. The running manager, fed through
  logcollector, fired on the 6th, the 7th or the 8th failure depending on the run (once
  twice, once not at 7): its analysis threads do not keep a strict order. Thresholds
  therefore keep a margin: 6 fires before the rate limit's 10 even two events late.

## Rejected options
- *Shipping logs over the network (syslog, the Wazuh agent):* another listener, another
  secret, and a Wazuh agent inside the distroless image; a shared read-only volume is the
  smallest surface on a single host. Hosting would ship the same lines to the SIEM's
  ingestion endpoint instead.
- *Letting Wazuh read the SQLite database:* it would see password hashes, sealed seeds and
  notes' ciphertext, and hold a lock on the database.
- *Asynchronous writes:* faster, but lines could be reordered or lost on a crash; the
  audit insert is synchronous already.

## Consequences
- Learners see their own activity on the platform as Wazuh alerts, and the rules that
  raise them are the ones the challenges teach them to write.
- The file grows with the audit log (rotated at 50 MiB, one previous file kept).
- Wazuh starts with `only-future-events`: lines written while it was stopped are not read
  when it starts. The database and `seq` show what Wazuh missed.
