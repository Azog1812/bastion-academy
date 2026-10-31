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
1. Generate a new key: `openssl rand -base64 32`.
2. Add it to the ring and make it active: `ENCRYPTION_KEYS=k1:<old>,k2:<new>`, `ACTIVE_KEY_ID=k2`. Deploy.
   New notes now use `k2`; old notes still open with `k1`.
3. Re-wrap old data keys and re-seal TOTP seeds: `node dist/cli.js rotate-keys` (note content is never decrypted).
4. Remove `k1` from the ring. Deploy. Destroy `k1`.

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
