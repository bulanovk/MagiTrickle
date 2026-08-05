#!/bin/bash
# test-http.sh — verify the SNI sniffer detects HTTP/1.1 Host headers
# on real connections through the router to IPs NOT already in an ipset.
#
# Mirrors the structure of test-sni.sh (TLS path) but exercises
# HTTP/1.1 on port 80. The router config (router/config.yaml) has
# enableHTTP: true and no port allow-list, so HTTP flows are
# intercepted by NFQUEUE.
#
# External DNS (1.1.1.1) is used so resolved IPs stay out of the
# wildcard-resolved ipset; otherwise the MT_SNI RETURN rule for the
# wildcard group short-circuits NFQUEUE before the sniffer sees the
# SYN. Proving the recent-observation endpoint contains our target
# domain confirms the HTTP parser (the only parser that could have
# matched a plain HTTP request) fired OnDomain for that flow.
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

# HTTP/1.1 targets. Chosen to NOT match any group rule in
# router/config.yaml — if a target domain matches a namespace/domain/
# wildcard rule, its resolved IP is added to that group's ipset and
# the MT_SNI chain's RETURN rule short-circuits NFQUEUE on every
# subsequent packet to that IP, so the sniffer never fires again.
# neverssl.com and wikipedia.org don't match any rule, so packets
# always reach NFQUEUE and the test is repeatable across runs.
declare -A TARGETS=(
  ["neverssl.com"]=""
  ["wikipedia.org"]=""
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

  say "HTTP/1.1 → ${HOST} @ ${IP}:80"
  if curl -s --max-time 10 --resolve "${HOST}:80:${IP}" \
          -A "Mozilla/5.0 (e2e-http)" \
          "http://${HOST}/" -o /dev/null -w '' 2>/dev/null; then
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
  fail "sniffer did not register any new hits (delta=$DELTA) — HTTP parser never fired"
fi
ok "sniffer registered $DELTA new hit(s)"

# Pull recent observations and assert each target host appears with
# its externally-resolved IP.
say "recent sniffer observations"
get_recent > /tmp/mt-http-recent.txt || fail "could not fetch /sniffer/recent"
head -n 20 /tmp/mt-http-recent.txt
echo

OBSERVED=0
for HOST in "${!TARGETS[@]}"; do
  IP="${TARGETS[$HOST]}"
  [ -z "$IP" ] && continue
  if grep -Fxq "${IP} ${HOST}" /tmp/mt-http-recent.txt; then
    ok "${HOST} (${IP}) — observed by sniffer"
    OBSERVED=$((OBSERVED + 1))
  else
    warn "${HOST} (${IP}) — NOT in recent observations"
  fi
done

if [ "$OBSERVED" -eq 0 ]; then
  fail "no target hosts found in recent observations — HTTP parser did not attribute the flow"
fi

say "result: $PASS/$((PASS+FAIL)) HTTP connections, $OBSERVED observed by sniffer"
# PASS the test as long as the sniffer observed at least one target.
# Transient network failures (timeout, RST) on individual targets
# shouldn't mask parser correctness — the recent-observations list
# still proves OnDomain fired on the matching host.
[ "$OBSERVED" -gt 0 ] && ok "HTTP sniffer path confirmed end-to-end" || fail "no sniffer observations for any target"