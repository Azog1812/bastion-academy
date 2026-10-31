#!/usr/bin/env bash
# Passkeys in a real browser (ADR 0016): the platform image, and the pinned Chromium of
# the xss-stored lab image with a virtual authenticator, on the platform's network
# namespace so the page is http://localhost:3000 (the default RP ID and origin).
#   docker build -t bastion:local . && docker compose --profile labs build lab-xss-stored
#   test/e2e/passkeys-browser.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
host() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

APP_IMAGE=${APP_IMAGE:-bastion:local}
BROWSER_IMAGE=${BROWSER_IMAGE:-bastion-lab-xss-stored:local}
P=bastion-pk-e2e
work=$(mktemp -d)
cleanup() { docker rm -f $P-app >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
cleanup
work=$(mktemp -d)

node dist/cli.js gen-secrets > "$work/e2e.env"
docker run -d --name $P-app --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  --env-file "$(host "$work/e2e.env")" -e NODE_ENV=production "$APP_IMAGE" >/dev/null

# The browser joins the platform's network namespace: localhost:3000 is the platform.
docker run --rm --network container:$P-app --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$(host "$PWD/test/e2e/passkeys-browser.mjs"):/e2e/passkeys-browser.mjs:ro" \
  --entrypoint node "$BROWSER_IMAGE" -e "
    const until = Date.now() + 30000;
    (async () => { for (;;) { try { if ((await fetch('http://localhost:3000/healthz')).ok) break; } catch {} if (Date.now() > until) process.exit(1); await new Promise(r => setTimeout(r, 500)); } await import('/e2e/passkeys-browser.mjs'); })();
  "
