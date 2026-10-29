#!/usr/bin/env bash
# End-to-end smoke test against a running instance, including the two
# properties that matter most: authentication and cross-user isolation.
#   ./scripts/smoke-test.sh http://127.0.0.1:3000
set -euo pipefail

BASE="${1:-http://127.0.0.1:3000}"
PASS="smoke test passphrase $RANDOM$RANDOM"
json=(-H 'content-type: application/json')
fail() { echo "✘ $*" >&2; exit 1; }
ok() { echo "✔ $*"; }

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

[[ "$(status "$BASE/healthz")" == 200 ]] || fail "healthz"
ok "liveness"

login() {
  local email="$1"
  curl -fsS -X POST "$BASE/v1/auth/register" "${json[@]}" -d "{\"email\":\"$email\",\"password\":\"$PASS\"}" > /dev/null
  curl -fsS -X POST "$BASE/v1/auth/login" "${json[@]}" -d "{\"email\":\"$email\",\"password\":\"$PASS\"}" | jq -r .accessToken
}

ALICE=$(login "alice.$RANDOM@smoke.test")
BOB=$(login "bob.$RANDOM@smoke.test")
ok "register + login"

NOTE=$(curl -fsS -X POST "$BASE/v1/notes" "${json[@]}" -H "authorization: Bearer $ALICE" \
  -d '{"title":"smoke","body":"top secret"}' | jq -r .id)
[[ "$(curl -fsS "$BASE/v1/notes/$NOTE" -H "authorization: Bearer $ALICE" | jq -r .body)" == "top secret" ]] || fail "owner read"
ok "encrypted note round-trip"

[[ "$(status "$BASE/v1/notes/$NOTE" -H "authorization: Bearer $BOB")" == 404 ]] || fail "IDOR: bob can read alice's note"
[[ "$(status -X DELETE "$BASE/v1/notes/$NOTE" -H "authorization: Bearer $BOB")" == 404 ]] || fail "IDOR: bob can delete alice's note"
ok "cross-user isolation (IDOR)"

[[ "$(status "$BASE/v1/notes" -H "authorization: Bearer invalid.token.value")" == 401 ]] || fail "forged token accepted"
[[ "$(status "$BASE/v1/admin/audit" -H "authorization: Bearer $ALICE")" == 403 ]] || fail "user reached admin route"
ok "authentication & function-level authorization"

headers=$(curl -fsS -D - -o /dev/null "$BASE/healthz" | tr -d '\r')
for h in "content-security-policy: default-src 'none'" "x-content-type-options: nosniff" "strict-transport-security:"; do
  grep -qi "^$h" <<< "$headers" || fail "missing header: $h"
done
grep -qi '^x-powered-by' <<< "$headers" && fail "x-powered-by leaked"
ok "security headers"

echo "all smoke tests passed"
