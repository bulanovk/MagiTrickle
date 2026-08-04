#!/bin/bash
# Fetch russia-blocked-geosite domain list, strip prefix, shuffle, trim to N.
# Default: 1000 domains. Override with GEN_DOMAINS_COUNT env var.
set -euo pipefail

COUNT="${GEN_DOMAINS_COUNT:-1000}"
RELEASE_URL="https://github.com/runetfreedom/russia-blocked-geosite/releases/latest/download/category-ads-all.txt"
OUT="${1:-domains.txt}"
TMP="$(mktemp)"

echo "[gen-domains] fetching $RELEASE_URL"
curl -fsSL --connect-timeout 10 --max-time 30 "$RELEASE_URL" -o "$TMP"

echo "[gen-domains] stripping prefix, keeping first $COUNT"
sed 's/^domain://' "$TMP" | shuf -n "$COUNT" > "$OUT"

rm -f "$TMP"
echo "[gen-domains] wrote $(wc -l < "$OUT") domains to $OUT"