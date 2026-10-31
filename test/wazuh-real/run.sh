#!/usr/bin/env bash
# Differential check of the Wazuh rule challenges (ADR 0014) against the real Wazuh:
# Bastion's evaluator and wazuh-logtest must alert on exactly the same things.
#   test/wazuh-real/run.sh          # needs Docker and the wazuh-manager image (~2.7 GB)
# Also run in CI by .github/workflows/wazuh.yml.
set -euo pipefail
cd "$(dirname "$0")/../.."

# Same image and digest as docker-compose.yml: one pin to maintain.
IMAGE=${WAZUH_MANAGER_IMAGE:-$(awk '/image: wazuh\/wazuh-manager:/ { print $2; exit }' docker-compose.yml)}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Git Bash on Windows: hand Docker Windows paths, and leave container paths alone.
export MSYS_NO_PATHCONV=1
host() { if command -v cygpath >/dev/null; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

npx tsx test/wazuh-real/prepare.ts "$(host "$work")"
for suite in "$work"/*/; do
  echo "== $(basename "$suite")"
  # nofile as in docker-compose.yml: analysisd raises its limit at start and logs an ERROR otherwise.
  docker run --rm --network none --memory 1500m --ulimit nofile=655360:655360 \
    -v "$(host "$suite"):/suite" -v "$(host "$PWD/test/wazuh-real/replay.sh"):/replay.sh:ro" \
    --entrypoint bash "$IMAGE" /replay.sh
done
npx tsx test/wazuh-real/compare.ts "$(host "$work")"
