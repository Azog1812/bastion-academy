#!/usr/bin/env bash
# Differential check against the real Wazuh, step 2: runs INSIDE the wazuh-manager
# image, with no network. Loads /suite/rules.xml next to the stock ruleset, refuses
# to go on if analysisd rejects them, then replays /suite/lines.log through
# wazuh-logtest in one session (so correlation works) and writes, per line, the
# final rule id and level to /suite/result.txt.
set -euo pipefail
cd /var/ossec

bash /etc/cont-init.d/0-wazuh-init >/tmp/init.log 2>&1 || { cat /tmp/init.log; exit 1; }
install -o wazuh -g wazuh -m 640 /suite/rules.xml etc/rules/zz_suite_rules.xml

# Rule syntax first: a rule Wazuh refuses must fail here, not be silently ignored.
if bin/wazuh-analysisd -t 2>&1 | grep -E "ERROR|CRITICAL"; then exit 1; fi

bin/wazuh-control start >/tmp/start.log 2>&1 || { cat /tmp/start.log; exit 1; }
for _ in $(seq 1 60); do [ -S queue/sockets/logtest ] && break; sleep 1; done

# One block per line, from "Phase 1" to the next: print its last rule id and level.
timeout 300 bin/wazuh-logtest < /suite/lines.log 2>&1 | awk '
  /^\*\*Phase 1/ { if (n) print id, lvl; n++; id = "none"; lvl = 0; p3 = 0 }
  /^\*\*Phase 3/ { p3 = 1 }
  p3 && /^\tid: / { gsub(/[^0-9]/, "", $2); id = $2 }
  p3 && /^\tlevel: / { gsub(/[^0-9]/, "", $2); lvl = $2 }
  END { if (n) print id, lvl }
' > /suite/result.txt
echo "$(wc -l < /suite/result.txt) results"
