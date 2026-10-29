#!/usr/bin/env bash
# Regenerates src/security/common-passwords.ts from SecLists (MIT licence).
# Keeps only entries of 12+ characters (shorter ones fail the length rule anyway).
set -euo pipefail
URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt"
OUT="src/security/common-passwords.ts"
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
curl -fsSL "$URL" -o "$tmp"
{
  echo "// Generated from SecLists (MIT) — Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt,"
  echo "// filtered to entries of 12+ characters (shorter ones are already rejected by the length rule)"
  echo "// and stripped of profanity."
  echo "// Regenerate with: scripts/update-password-blocklist.sh"
  echo "export const COMMON_PASSWORDS: ReadonlySet<string> = new Set(["
  tr -d '\r' < "$tmp" | awk 'length($0) >= 12' | tr '[:upper:]' '[:lower:]' | sort -u \
    | grep -viE 'fuck|nigg|cunt|whore|bitch|slut|pussy|dick|cock|penis|vagina|sex|porn|fag|rape|hitler|nazi|shit|asshole|boob|tits' \
    | node -e 'require("readline").createInterface({input:process.stdin}).on("line",l=>console.log("  "+JSON.stringify(l)+","))'
  echo "]);"
} > "$OUT"
echo "wrote $(grep -c '^  "' "$OUT") entries to $OUT"
