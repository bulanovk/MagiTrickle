#!/bin/bash
# test-http2.sh — verify the SNI sniffer detects HTTP/2 :authority
# pseudo-headers on real connections through the router to IPs NOT
# already in an ipset.
#
# Mirrors the structure of test-sni.sh (TLS) and test-http.sh (HTTP/1.1).
# The router config has enableHTTP2: true and 80 listed in allowedPorts,
# so h2c flows are intercepted by NFQUEUE.
#
# External DNS (1.1.1.1) is used so resolved IPs stay out of the
# wildcard-resolved ipset; otherwise the MT_SNI RETURN rule for the
# wildcard group short-circuits NFQUEUE before the sniffer sees the
# SYN.
#
# The HTTP/2 client preface + a HEADERS frame containing :authority
# is sent on every connection. Even if the chosen target does not
# actually support h2c (and resets the connection), the sniffer will
# still see the first packet through NFQUEUE — that is enough to
# prove the h2c parser fires. We don't depend on getting a 200 back.
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

# Send a minimal HTTP/2 connection: preface + SETTINGS(0) + HEADERS
# with :authority=<host> and :path=/. The HPACK-encoded block uses
# the literal-with-never-indexed form so :authority is preserved
# verbatim — matches what real h2c clients send.
send_h2c_authority() {
  local host="$1" ip="$2"
  python3 - "$host" "$ip" <<'PY'
import socket, struct, sys

host, ip = sys.argv[1], sys.argv[2]

# HTTP/2 connection preface (RFC 7540 §3.5).
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def frame(ftype: int, flags: int, sid: int, payload: bytes) -> bytes:
    # HTTP/2 frame header: 3-byte length + 1-byte type + 1-byte flags
    # + 4-byte stream id. The flags field is a single byte; using
    # ">3sBI" would pack it as a uint32 and shift every subsequent
    # field by 3 bytes, so the parser (and the server) would walk
    # the wrong offsets and never see the :authority pseudo-header.
    return struct.pack(">3sBB", struct.pack(">I", len(payload))[1:], ftype, flags) + \
        struct.pack(">I", sid & 0x7fffffff) + payload

def hpack_indexed(idx: int) -> bytes:
    # 1-bit prefix 1, 7-bit index.
    return bytes([0x80 | (idx & 0x7f)])

def hpack_literal(name_idx: int, value: bytes) -> bytes:
    # 01 <name_idx 7bit> <value>
    out = bytes([0x40 | (name_idx & 0x7f)])
    out += bytes([len(value)]) + value
    return out

# HEADERS frame: :method=GET(idx 2), :path=/(idx 4),
# :scheme=http(idx 6), :authority=<host>(literal 1).
headers = hpack_indexed(2) + hpack_indexed(4) + hpack_indexed(6) + hpack_literal(1, host.encode("ascii"))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect((ip, 80))
    s.sendall(PREFACE + frame(0x4, 0x0, 0, b"") + frame(0x1, 0x4, 1, headers))
    # Drain anything the server sends (or wait for RST).
    try:
        s.recv(64)
    except socket.timeout:
        pass
finally:
    s.close()
PY
}

get_hits() {
  curl -sf "${WEBUI}/api/v1/sniffer/stats" | grep -o '"hits_total":[0-9]*' | cut -d: -f2
}
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

# Targets chosen to NOT match any group rule in router/config.yaml —
# if a target domain matches a rule, its IP is added to that group's
# ipset and the MT_SNI chain's RETURN rule short-circuits NFQUEUE on
# every subsequent packet, so the sniffer never fires again. We need
# domains that fall outside all configured rules so packets always
# reach NFQUEUE and the test is repeatable across runs.
declare -A TARGETS=(
  ["neverssl.com"]=""
  ["wikipedia.org"]=""
)

PASS=0
FAIL=0
SEND_FAIL=0

for HOST in "${!TARGETS[@]}"; do
  IP=$(dig +short @"${EXTERNAL_DNS}" A "${HOST}" 2>/dev/null | awk '!/^;/ {print; exit}')
  if [ -z "$IP" ]; then
    warn "${HOST} — could not resolve via ${EXTERNAL_DNS}"
    FAIL=$((FAIL + 1))
    continue
  fi
  TARGETS[$HOST]=$IP

  say "HTTP/2 h2c → ${HOST} @ ${IP}:80"
  if send_h2c_authority "${HOST}" "${IP}" 2>/dev/null; then
    ok "${HOST} — preface + HEADERS sent"
    PASS=$((PASS + 1))
  else
    warn "${HOST} — send failed (network issue)"
    SEND_FAIL=$((SEND_FAIL + 1))
  fi
done

# Give the sniffer a moment to process the packets.
sleep 1

HITS=$(get_hits)
say "sniffer hits: $BASELINE → $HITS"
DELTA=$((HITS - BASELINE))
if [ "$DELTA" -le 0 ]; then
  fail "sniffer did not register any new hits (delta=$DELTA) — HTTP/2 parser never fired"
fi
ok "sniffer registered $DELTA new hit(s)"

say "recent sniffer observations"
get_recent > /tmp/mt-http2-recent.txt || fail "could not fetch /sniffer/recent"
head -n 20 /tmp/mt-http2-recent.txt
echo

OBSERVED=0
for HOST in "${!TARGETS[@]}"; do
  IP="${TARGETS[$HOST]}"
  [ -z "$IP" ] && continue
  if grep -Fxq "${IP} ${HOST}" /tmp/mt-http2-recent.txt; then
    ok "${HOST} (${IP}) — observed by sniffer"
    OBSERVED=$((OBSERVED + 1))
  else
    warn "${HOST} (${IP}) — NOT in recent observations"
  fi
done

if [ "$OBSERVED" -eq 0 ]; then
  fail "no target hosts found in recent observations — HTTP/2 parser did not attribute the flow"
fi

say "result: $PASS/$((PASS+FAIL+SEND_FAIL)) h2c sends, $OBSERVED observed by sniffer"
[ "$OBSERVED" -gt 0 ] && ok "HTTP/2 sniffer path confirmed end-to-end"