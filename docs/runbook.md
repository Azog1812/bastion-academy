# Operations runbook

## First deployment
```bash
npm ci && npm run build
node dist/cli.js gen-secrets > .env.production      # store these in your secret manager
kubectl apply -k deploy/k8s
kubectl -n bastion create secret generic bastion-secrets \
  --from-literal=JWT_SECRET=... --from-literal=AUDIT_HMAC_KEY=... --from-literal=FLAG_HMAC_KEY=... --from-literal=ENCRYPTION_KEYS=... \
  --from-literal=METRICS_TOKEN=...
# first admin, out-of-band (there is deliberately no HTTP route for this).
# The image has no shell, but exec can run the Node binary directly:
kubectl -n bastion exec deploy/bastion -- /nodejs/bin/node dist/cli.js promote you@example.com
```

## Labs (v5)

```bash
node dist/cli.js gen-secrets > .env          # includes LAB_RUNNER_TOKEN
docker compose --profile labs build          # lab images, once and after each lab change
docker compose up --build                    # platform, lab runner, lab gateway
```

- **"This lab is not built yet"**: the image is missing, run the build command above.
- **A lab answers 502**: it is starting (a second or two), stopped or expired. Stop it and
  start it again from the challenge page. After `docker compose up`, the runner re-attaches
  the gateway to every live lab by itself.
- **List or clean lab containers** (they are not part of the compose project):
  `docker ps --filter label=bastion.lab=1` · expired ones are removed within a minute;
  to remove all of them: `docker rm -f $(docker ps -aq --filter label=bastion.lab=1)` then
  `docker network prune --filter label=bastion.lab=1`.
- **Stronger sandbox**: install gVisor on the host and set `LAB_RUNTIME: runsc` on the
  `lab-runner` service.
- **Rotating `LAB_RUNNER_TOKEN`**: generate a new value, update `.env`, then
  `docker compose up -d` (platform and runner restart together; running labs survive).

## Wazuh (ADR 0013)

```bash
node dist/cli.js gen-secrets > .env          # includes WAZUH_ADMIN/DASHBOARD/API_PASSWORD
docker compose --profile wazuh up -d         # once: certificates, users, then the stack (~4 GiB RAM, ~7 GiB disk)
```

Afterwards learners start and stop it from the Wazuh module card. Dashboard:
**https://localhost:8443**, user `admin`, password `WAZUH_ADMIN_PASSWORD`. The browser warns
about the certificate: it comes from the private CA made at setup (`wazuh-certs` volume).

- **"Not installed yet"** in the UI: the containers do not exist, run the command above.
- **Stuck on "starting"**: the indexer needs one to two minutes; check
  `docker logs bastion-wazuh-indexer`. Below ~4 GiB of free RAM it may never become healthy.
- **It stopped by itself**: the runner stops it after 8 hours (log line
  `environments stopped after their maximum run time`).
- **Changing a password after the first start**: the indexer only reads `internal_users.yml`
  when it creates its security index. Either reset everything
  (`docker compose --profile wazuh down -v`, update `.env`, `up -d` again: alerts are lost), or
  run `securityadmin.sh` inside `bastion-wazuh-indexer` with the admin certificate.
- **Removing it**: `docker compose --profile wazuh down -v` (containers, certificates, data).
- **Bastion's own alerts** (ADR 0015): the platform appends its audit log to
  `/var/log/bastion/audit.json` (volume `bastion-audit`), the manager reads it with
  `deploy/wazuh/bastion_rules.xml`. In the dashboard, filter on `rule.groups: bastion`.
  Lines written while Wazuh was stopped are not read at its next start; the database
  has them (`GET /v1/admin/audit`), and `seq` shows the gap.
- **Checking the rules after an edit or a Wazuh upgrade**: `test/wazuh-real/run.sh`
  (offline, in the pinned image); CI runs it too.

## Observability (ADR 0011)

```bash
docker compose --profile observability up -d   # Prometheus on http://127.0.0.1:9090
```

- **Alerts tab**: the eleven rules of `deploy/prometheus/alerts.yml`; each section
  below named after an alert says what to do.
- **Target `bastion` is down** while the API answers: the token differs between the
  platform and Prometheus (both read `METRICS_TOKEN` from `.env`); `docker compose up -d`
  after editing `.env` restarts both.
- **Scrape by hand** (the port is not published; Prometheus' image has busybox `wget`):
  `docker compose exec prometheus sh -c 'wget -qO- --header "Authorization: Bearer $(cat /run/secrets/metrics_token)" http://bastion:9464/metrics'`.
- **Changing an alert**: edit `alerts.yml` *and* `alerts.test.yml`, then
  `docker run --rm -v "$PWD/deploy/prometheus:/rules:ro" -w /rules --entrypoint promtool prom/prometheus:v3.15.1 test rules alerts.test.yml`.
- **Rotating `METRICS_TOKEN`**: new value in `.env` (or the Kubernetes secret), restart
  the platform and Prometheus together.

## Rotating the encryption key (KEK)
**With Vault** (ADR 0019): `node dist/cli.js rotate-keys` adds a new Transit key version and
has Vault re-wrap every DEK and TOTP seed (no DEK leaves Vault). Old versions still decrypt;
retiring them (`min_decryption_version`) needs an admin token, never Bastion's.

**With the local ring:**
1. Generate a new key: `openssl rand -base64 32`.
2. Add it to the ring and make it active: `ENCRYPTION_KEYS=k1:<old>,k2:<new>`, `ACTIVE_KEY_ID=k2`. Deploy.
   New notes now use `k2`; old notes still open with `k1`.
3. Re-wrap old data keys and re-seal TOTP seeds: `node dist/cli.js rotate-keys` (note content is never decrypted).
4. Remove `k1` from the ring. Deploy. Destroy `k1`.

## Vault (ADR 0019)

```bash
docker compose -f docker-compose.yml -f docker-compose.vault.yml up -d
docker compose -f docker-compose.yml -f docker-compose.vault.yml exec bastion /nodejs/bin/node dist/cli.js rotate-keys
```

- **First start**: `vault-init` initialises Vault, creates the Transit key (derived, not
  exportable, not deletable), the `bastion` policy and AppRole, then revokes the root token.
  Its log ends with `root token revoked`. Later starts only unseal.
- **Moving an existing install**: keep `ENCRYPTION_KEYS`/`ACTIVE_KEY_ID` in `.env`, start
  with the overlay, run `rotate-keys` once (every row goes under `vault:bastion-kek:vN`),
  then remove the ring from `.env` and restart.
- **Notes answer 503** ("key service unavailable"): Vault is sealed or down. Check the
  `vault` service; after a Vault restart, `up -d` runs `vault-init` again, which unseals.
  This is not tampering: `BastionCiphertextTampering` stays quiet.
- **The platform refuses to start** with `key service check failed`: the Transit key is
  missing or unsafe (exportable, deletable, not derived), or the AppRole login fails. The
  message names the property.
- **Who used the key**: Vault's audit log is its container log (`logs vault`), one line per
  request, secrets HMAC-ed.
- **Lost `vault-keys` volume**: the unseal key is gone and Vault cannot be opened. Back it
  up like the database, separately from it.

## Rotating the JWT key
Replace `JWT_SECRET` and redeploy. Every access token becomes invalid (users refresh
transparently; refresh tokens are not JWTs and stay valid).

## Alert: `auth.refresh_reuse_detected`
Prometheus: `BastionRefreshTokenReuse` (critical).
A refresh token was replayed → likely token theft. The family is already revoked and
the user's access tokens invalidated. Check the IPs in the audit entries around the
event, contact the user, recommend a password change.

## Alert: `ciphertext integrity failure — possible tampering` in logs
Prometheus: `BastionCiphertextTampering` (critical).
Someone modified encrypted rows directly in the database. Treat as a database
compromise: isolate, snapshot the volume for forensics, run `verify-audit`, rotate
all secrets, restore from a known-good backup.

## Alert: `verify-audit` returns `"valid": false`
The audit trail was altered at `firstInvalidSeq`. Preserve the database file as
evidence before any other action; entries before that sequence number are trustworthy.

## Alert: repeated `authz.denied`
Prometheus: `BastionAuthorizationProbing`.
A user is probing other users' object ids (IDOR attempts) or admin routes. Review the
actor's activity; consider disabling the account.

## Alert: `BastionCredentialStuffing`
Also `BastionAccountLockouts` and `BastionMfaBruteForce`. Many failed logins across
accounts: a password spray or a leaked-credentials list. Per-IP limits and per-account
lockout slow it down, they do not stop a distributed attempt. Look at the `auth.login`
failures in the audit log: few IPs → block them upstream; many accounts locked → the
lockout is being used as a DoS, consider raising `MAX_FAILED_LOGINS` temporarily.
Wrong MFA codes mean the attacker already holds passwords: force a password reset for
the accounts concerned.

## Alert: `BastionSharedFlag`
A learner submitted another learner's flag. Not a security incident: the audit entry
(`challenge.flag_shared`) names both accounts; the score was not granted.

## Alert: `BastionAuditExportFailing`
Audit entries are not reaching `AUDIT_EXPORT_FILE`: Wazuh is blind to them. The
database still has every entry. Look for `audit export:` in the platform's logs: a full
disk (`docker system df`), or the `bastion-audit` volume missing or read-only. Once
fixed, compare `seq` in Wazuh with `GET /v1/admin/audit` to see what Wazuh missed.

## Alert: `BastionDown`
Prometheus cannot scrape the platform for two minutes. Check `/healthz` on the API: if
it answers, the metrics token or the `metrics` network is wrong (see Observability);
otherwise the platform is down, read its logs.

## Alert: `BastionHighErrorRate`
More than 5 % of requests end in a 5xx for ten minutes (or `BastionEventLoopBlocked`:
the event loop is stalled). Read the `unhandled error` log lines with their `requestId`;
a full disk or a corrupted database shows up in `/readyz`.

## Alert: `BastionMetricsCardinality`
A metric reached its series cap and drops samples. It should never happen: labels come
from closed sets. Find the metric with too many series
(`count by (__name__)({__name__=~".+"})`) and fix the label that takes request input.
