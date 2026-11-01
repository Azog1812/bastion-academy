#!/usr/bin/env bash
# Tests of deploy/alertmanager/alertmanager.yml (ADR 0018), offline, with the pinned image.
#  1. amtool check-config: the file parses and every receiver exists.
#  2. Routing: each alert of deploy/prometheus/alerts.yml, with its labels, reaches the
#     receiver it is written for (amtool config routes test --verify.receivers).
#  3. Inhibition, on a real Alertmanager: alerts are posted to its API and the ones that
#     must be muted come back with inhibitedBy set (amtool cannot test inhibition).
# Run locally or in CI: deploy/alertmanager/routes.test.sh
set -euo pipefail
cd "$(dirname "$0")"
export MSYS_NO_PATHCONV=1
host() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

# Same image and digest as the alertmanager service in docker-compose.yml: keep them in sync.
IMAGE=${ALERTMANAGER_IMAGE:-prom/alertmanager:v0.34.2@sha256:39d8bb3966c694a124428a3a88fbcffd40bd069129ecd47c059f8a3f17c55f3b}
CONF=$(host "$PWD")
amtool() { docker run --rm --network none -v "$CONF:/am:ro" -w /am --entrypoint amtool "$IMAGE" "$@"; }

amtool check-config alertmanager.yml

fail=0
expect() {
  local receiver=$1
  shift
  if amtool config routes test --config.file=alertmanager.yml --verify.receivers="$receiver" "$@" >/dev/null; then
    echo "ok    $* -> $receiver"
  else
    echo "FAIL  $* -> expected $receiver, got $(amtool config routes test --config.file=alertmanager.yml "$@")"
    fail=1
  fi
}

# Every alert of alerts.yml, with the labels it carries.
expect pager alertname=BastionRefreshTokenReuse severity=critical action=auth.refresh_reuse_detected outcome=denied
expect pager alertname=BastionCiphertextTampering severity=critical
expect pager alertname=BastionDown severity=critical job=bastion
expect pager alertname=AlertmanagerUnreachable severity=critical
expect pager alertname=AlertmanagerNotificationsFailing severity=critical integration=email
expect secops alertname=BastionCredentialStuffing severity=warning
expect secops alertname=BastionAccountLockouts severity=warning
expect secops alertname=BastionMfaBruteForce severity=warning
expect secops alertname=BastionAuthorizationProbing severity=warning
expect secops alertname=BastionAuditExportFailing severity=warning
expect secops alertname=BastionHighErrorRate severity=warning
expect secops alertname=BastionEventLoopBlocked severity=warning
expect secops alertname=BastionMetricsCardinality severity=warning
expect trainers alertname=BastionSharedFlag severity=info action=challenge.flag_shared
expect watchdog alertname=Watchdog severity=none
# The watchdog is matched before severity: a mislabelled one still goes to its receiver.
expect watchdog alertname=Watchdog severity=critical
# An alert nobody routed (a new rule without severity) still reaches a human.
expect secops alertname=SomethingNew
[ "$fail" = 0 ] || exit 1

# Inhibition, live. Loopback only, random port, removed on exit.
name=bastion-am-test-$$
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" -p 127.0.0.1::9093 -v "$CONF:/etc/alertmanager:ro" "$IMAGE" \
  --config.file=/etc/alertmanager/alertmanager.yml --storage.path=/tmp >/dev/null
port=$(docker port "$name" 9093/tcp | head -1 | sed 's/.*://')
url="http://127.0.0.1:$port/api/v2"
for _ in $(seq 1 30); do curl -fs "$url/status" >/dev/null 2>&1 && break; sleep 1; done

alert() { printf '{"labels":{"alertname":"%s","severity":"%s"},"startsAt":"%s"}' "$1" "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
post() { curl -fs -X POST -H 'Content-Type: application/json' "$url/alerts" -d "[$(IFS=,; echo "$*")]" >/dev/null; }
# Expected state per alert name: "muted" (inhibited) or "sent".
check() {
  sleep 2
  curl -fs "$url/alerts" | node -e '
    const alerts = JSON.parse(require("fs").readFileSync(0, "utf8"));
    const state = Object.fromEntries(alerts.map((a) => [a.labels.alertname, a.status.inhibitedBy.length > 0 ? "muted" : "sent"]));
    let ok = true;
    for (const pair of process.argv.slice(1)) {
      const [name, want] = pair.split("=");
      console.log(`${state[name] === want ? "ok  " : "FAIL"}  ${name} ${want}`);
      if (state[name] !== want) ok = false;
    }
    process.exit(ok ? 0 : 1);
  ' "$@"
}

# 1. Bastion is up: the cause is reported, its consequence is muted.
post "$(alert BastionCredentialStuffing warning)" "$(alert BastionAccountLockouts warning)"   "$(alert BastionEventLoopBlocked warning)" "$(alert BastionHighErrorRate warning)"   "$(alert BastionSharedFlag info)" "$(alert Watchdog none)"
check BastionCredentialStuffing=sent BastionAccountLockouts=muted BastionEventLoopBlocked=sent   BastionHighErrorRate=muted BastionSharedFlag=sent Watchdog=sent

# 2. Bastion goes down: one page for the outage, its symptoms muted, other critical alerts and the watchdog kept.
post "$(alert BastionDown critical)" "$(alert BastionRefreshTokenReuse critical)"
check BastionDown=sent BastionRefreshTokenReuse=sent Watchdog=sent   BastionCredentialStuffing=muted BastionEventLoopBlocked=muted BastionSharedFlag=muted

echo "Alertmanager routing and inhibition: all checks passed"
