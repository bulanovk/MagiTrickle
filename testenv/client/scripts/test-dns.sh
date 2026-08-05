#!/bin/bash
# Plain DNS path — DNS-MITM. Router IP is resolved at runtime.
set -euo pipefail

ROUTER_IP=${ROUTER_IP:-$(ip route show default | awk '{print $3; exit}')}
WEBUI=${WEBUI:-http://$ROUTER_IP:8080}
echo "router=$ROUTER_IP webui=$WEBUI"

echo "== DNS-MITM path =="
echo "-- dig example.com (A)"
dig +short @"$ROUTER_IP" example.com A | tee /tmp/dns_a.txt
echo "-- curl example.com (uses system resolver → router → magitrickled)"
curl -sS -o /dev/null -w 'http %{http_code} time=%{time_total}s\n' http://example.com/
echo "-- dig cloudflare.com (A)"
dig +short @"$ROUTER_IP" cloudflare.com A | head -n 4

echo
echo "-- Inspect router state"
echo "WebUI groups:"
curl -fsS "$WEBUI/api/v1/groups" | head -c 400; echo
echo "Sniffer stats:"
curl -fsS "$WEBUI/api/v1/sniffer/stats" 2>/dev/null | head -c 400 || echo "(no sniffer endpoint)"
echo
