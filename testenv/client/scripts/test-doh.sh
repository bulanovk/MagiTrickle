#!/bin/bash
# DoH path — curl encrypts DNS to 1.1.1.1 directly, so the DNS-MITM
# proxy on the router never sees the lookup. Only the SNI sniffer can
# attribute the resulting TLS connection to a domain.
set -euo pipefail

ROUTER_IP=${ROUTER_IP:-$(ip route show default | awk '{print $3; exit}')}
WEBUI=${WEBUI:-http://$ROUTER_IP:8080}
echo "router=$ROUTER_IP webui=$WEBUI"

DOHOST="https://cloudflare-dns.com/dns-query"
echo "== DoH / SNI sniffer path =="

echo "-- curl --doh-url (HTTPS DoH, SNI=cloudflare-dns.com)"
curl -sS --doh-url "$DOHOST" -o /dev/null -w 'doh %{http_code} time=%{time_total}s\n' \
  "https://example.com/" || true

echo "-- curl plain HTTPS to example.com (SNI=example.com)"
IP=$(dig +short @"$ROUTER_IP" example.com | head -n1)
echo "  resolved example.com -> $IP"
curl -sSI -o /dev/null -w 'https %{http_code} time=%{time_total}s\n' \
  --resolve example.com:443:$IP https://example.com/ || true

echo "-- openssl s_client (TLS-only — no HTTP at all)"
echo Q | timeout 5 openssl s_client -connect example.com:443 -servername example.com \
  -verify_quiet 2>/dev/null | head -n 5 || true

echo
echo "-- Inspect router state"
echo "Sniffer stats:"
curl -fsS "$WEBUI/api/v1/sniffer/stats" 2>/dev/null | head -c 400 || echo "(no sniffer endpoint)"
echo
echo "Sniffer recent observations:"
curl -fsS "$WEBUI/api/v1/sniffer/recent?limit=10" 2>/dev/null | head -c 600 || echo "(no sniffer endpoint)"
echo
