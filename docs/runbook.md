# Operations runbook

## First deployment
```bash
npm ci && npm run build
node dist/cli.js gen-secrets > .env.production      # store these in your secret manager
kubectl apply -k deploy/k8s
kubectl -n bastion create secret generic bastion-secrets \
  --from-literal=JWT_SECRET=... --from-literal=AUDIT_HMAC_KEY=... --from-literal=FLAG_HMAC_KEY=... --from-literal=ENCRYPTION_KEYS=...
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
A refresh token was replayed → likely token theft. The family is already revoked and
the user's access tokens invalidated. Check the IPs in the audit entries around the
event, contact the user, recommend a password change.

## Alert: `ciphertext integrity failure — possible tampering` in logs
Someone modified encrypted rows directly in the database. Treat as a database
compromise: isolate, snapshot the volume for forensics, run `verify-audit`, rotate
all secrets, restore from a known-good backup.

## Alert: `verify-audit` returns `"valid": false`
The audit trail was altered at `firstInvalidSeq`. Preserve the database file as
evidence before any other action; entries before that sequence number are trustworthy.

## Alert: repeated `authz.denied`
A user is probing other users' object ids (IDOR attempts) or admin routes. Review the
actor's activity; consider disabling the account.
