#!/bin/bash
# test-tls.sh — verify the SNI sniffer detects TLS ClientHello SNI for
# real connections through the router to IPs NOT already in an ipset.
#
# Mirrors the structure of test-http.sh (HTTP/1.1) and test-http2.sh
# (HTTP/2 h2c) — same baseline-hits / delta / recent-observations
# assertion pattern.
#
# External DNS (1.1.1.1) is used so resolved IPs stay out of the
# wildcard-resolved ipset; otherwise the MT_SNI RETURN rule for the
# wildcard group short-circuits NFQUEUE before the sniffer sees the
# SYN. We don't go through the router's DNS-MITM for the same reason.
set -euo pipefail

ROUTER_IP=${ROUTER_IP:-$(ip route show default | awk '{print $3; exit}')}
WEBUI=${WEBUI:-http://${ROUTER_IP}:8080}
export ROUTER_IP WEBUI

# shellcheck source=./_lib.sh
source "$(dirname "$0")/_lib.sh"

EXTERNAL_DNS="1.1.1.1"

say()  { printf '\033[1;36m▶ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*"; exit 1; }

say "router reachable: $ROUTER_IP"
curl -fsS "${WEBUI}/api/v1/groups" >/dev/null \
    && ok "API up" \
    || fail "API down"

# Baseline sniffer hit count so we can prove THIS test caused new hits.
get_hits() {
  curl -sf "${WEBUI}/api/v1/sniffer/stats" | grep -o '"hits_total":[0-9]*' | cut -d: -f2
}
# Recent observations as a flat list of "ip domain" lines.
get_recent() {
  curl -sf "${WEBUI}/api/v1/sniffer/recent?limit=50" \
    | python3 -c "import json,sys
for o in json.load(sys.stdin).get('observations', []):
    print(o['ip'], o['domain'])"
}
BASELINE=$(get_hits)
say "baseline sniffer hits: $BASELINE"

# Flush attributed IPs from a previous run so the MT_SNI RETURN rule
# can't short-circuit NFQUEUE on this test's targets. Both the test
# group and the wildcard mt-stress group must be reset: the wildcard
# captures every probed domain on the stand.
say "flushing sniffer state for all enabled groups"
reset_sniffer_state || fail "sniffer reset failed"

# TLS targets. Resolved via external DNS to keep IPs out of the
# wildcard-resolved ipset. HTTPS on port 443 — the router publishes
# 443 from the host network namespace, so the packet crosses both the
# bridge and the host.
declare -A TARGETS=(
  ["google.com"]=""
  ["www.google.com"]=""
)

PASS=0
FAIL=0

for HOST in "${!TARGETS[@]}"; do
  IP=$(dig +short @"${EXTERNAL_DNS}" A "${HOST}" 2>/dev/null | awk '!/^;/ {print; exit}')
  if [ -z "$IP" ]; then
    warn "${HOST} — could not resolve via ${EXTERNAL_DNS}"
    FAIL=$((FAIL + 1))
    continue
  fi
  TARGETS[$HOST]=$IP

  say "HTTPS → ${HOST} @ ${IP}:443"
  if curl -sk --max-time 10 --resolve "${HOST}:443:${IP}" \
          -A "Mozilla/5.0 (e2e-tls)" \
          "https://${HOST}/" -o /dev/null -w '' 2>/dev/null; then
    ok "${HOST} — connection OK"
    PASS=$((PASS + 1))
  else
    warn "${HOST} — connection failed (network issue, not sniffer)"
    FAIL=$((FAIL + 1))
  fi
done

HITS=$(get_hits)
say "sniffer hits: $BASELINE → $HITS"
DELTA=$((HITS - BASELINE))
if [ "$DELTA" -le 0 ]; then
  fail "sniffer did not register any new hits (delta=$DELTA) — TLS ClientHello never fired OnDomain"
fi
ok "sniffer registered $DELTA new hit(s)"

# Pull recent observations and assert each target host appears with
# its externally-resolved IP.
say "recent sniffer observations"
get_recent > /tmp/mt-tls-recent.txt || fail "could not fetch /sniffer/recent"
head -n 20 /tmp/mt-tls-recent.txt
echo

OBSERVED=0
for HOST in "${!TARGETS[@]}"; do
  IP="${TARGETS[$HOST]}"
  [ -z "$IP" ] && continue
  if grep -Fxq "${IP} ${HOST}" /tmp/mt-tls-recent.txt; then
    ok "${HOST} (${IP}) — observed by sniffer"
    OBSERVED=$((OBSERVED + 1))
  else
    warn "${HOST} (${IP}) — NOT in recent observations"
  fi
done

if [ "$OBSERVED" -eq 0 ]; then
  fail "no target hosts found in recent observations — TLS parser did not attribute the flow"
fi

say "result: $PASS/$((PASS+FAIL)) HTTPS connections, $OBSERVED observed by sniffer"
# PASS as long as the sniffer observed at least one target — transient
# network failures on individual targets shouldn't mask parser correctness.
[ "$OBSERVED" -gt 0 ] && ok "TLS sniffer path confirmed end-to-end" || fail "no sniffer observations for any target"