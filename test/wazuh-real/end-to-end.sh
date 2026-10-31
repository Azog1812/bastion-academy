#!/usr/bin/env bash
# End-to-end check of ADR 0015 with real containers: the platform writes its audit log
# to a volume, a real wazuh-manager reads it (log_format json, bastion_rules.xml), and
# alerts.json must show the Bastion rules. Throwaway names, everything removed at exit.
#   docker build -t bastion:local . && test/wazuh-real/end-to-end.sh
# Needs about 1.5 GB of free RAM (the manager alone, no indexer or dashboard).
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
host() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

APP_IMAGE=${APP_IMAGE:-bastion:local}
MANAGER=$(awk '/image: wazuh\/wazuh-manager:/ { print $2; exit }' docker-compose.yml)
P=bastion-e2e
PORT=3999
work=$(mktemp -d)

cleanup() {
  docker rm -f $P-app $P-manager >/dev/null 2>&1 || true
  docker volume rm $P-audit $P-data >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
cleanup
work=$(mktemp -d)

node dist/cli.js gen-secrets > "$work/e2e.env"
docker volume create $P-audit >/dev/null
docker volume create $P-data >/dev/null

# As in docker-compose.yml: no network, the audit volume read-only, the rules copied in at start.
docker run -d --name $P-manager --network none --memory 1400m --ulimit nofile=655360:655360 \
  -v "$(host "$PWD/deploy/wazuh/wazuh_manager.conf"):/wazuh-config-mount/etc/ossec.conf:ro" \
  -v "$(host "$PWD/deploy/wazuh/bastion_rules.xml"):/wazuh-config-mount/etc/rules/bastion_rules.xml:ro" \
  -v $P-audit:/var/log/bastion:ro "$MANAGER" >/dev/null

docker run -d --name $P-app --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  --env-file "$(host "$work/e2e.env")" -e NODE_ENV=production -e AUDIT_EXPORT_FILE=/var/log/bastion/audit.json \
  -v $P-data:/data -v $P-audit:/var/log/bastion -p 127.0.0.1:$PORT:3000 "$APP_IMAGE" >/dev/null

for _ in $(seq 1 60); do curl -fs http://127.0.0.1:$PORT/healthz >/dev/null && break; sleep 1; done
curl -fs http://127.0.0.1:$PORT/healthz >/dev/null || { echo "platform did not start:"; docker logs $P-app 2>&1 | tail -5; exit 1; }
# Wazuh reads only lines written after it opened the file: wait for it.
for _ in $(seq 1 120); do
  docker exec $P-manager grep -q "Analyzing file: '/var/log/bastion/audit.json'" /var/ossec/logs/ossec.log 2>/dev/null && break
  sleep 2
done

post() { curl -s -H 'Content-Type: application/json' -X POST "http://127.0.0.1:$PORT$1" -d "$2" >/dev/null; }
post /v1/auth/register '{"email":"e2e@example.com","password":"correct horse battery staple 42"}'
token=$(curl -s -H 'Content-Type: application/json' -X POST http://127.0.0.1:$PORT/v1/auth/login \
  -d '{"email":"e2e@example.com","password":"correct horse battery staple 42"}' | sed -E 's/.*"accessToken":"([^"]+)".*/\1/')
curl -s -H "Authorization: Bearer $token" http://127.0.0.1:$PORT/v1/admin/audit >/dev/null # a learner on an admin route
# Eight: register and login use two of the ten auth requests the rate limit allows per address.
for _ in $(seq 1 ${FAILURES:-8}); do post /v1/auth/login '{"email":"nobody@example.com","password":"wrong password here"}'; done

alerts=""
for _ in $(seq 1 30); do
  alerts=$(docker exec $P-manager cat /var/ossec/logs/alerts/alerts.json 2>/dev/null || true)
  grep -q '"id":"100209"' <<<"$alerts" && grep -q '"id":"100203"' <<<"$alerts" && break
  sleep 2
done
# Let the last lines land before counting.
sleep 5
alerts=$(docker exec $P-manager cat /var/ossec/logs/alerts/alerts.json 2>/dev/null || true)
echo "rules raised: $(grep -o '"rule":{[^}]*"id":"1002[0-9][0-9]"' <<<"$alerts" | grep -o '"id":"[0-9]*"' | sort | uniq -c | tr -s ' ' | paste -sd ',')"
mode=$(docker run --rm -v $P-audit:/a:ro --entrypoint stat "$MANAGER" -c %a /a/audit.json)
echo "audit.json mode: $mode"
grep -q '"id":"100203"' <<<"$alerts" && grep -q '"id":"100209"' <<<"$alerts" && [ "$mode" = 600 ] || { echo "FAILED"; exit 1; }
echo "OK: the platform's audit log reaches Wazuh and raises its rules"
