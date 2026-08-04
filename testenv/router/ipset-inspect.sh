#!/bin/bash
# Helper to peek at router ipset/iptables state. Run inside the
# *router* container: `docker compose exec router ipset-inspect`
set -euo pipefail
echo "== mt_* ipsets =="
ipset list 2>/dev/null | head -n 200
echo
echo "== MT_* chains =="
for t in filter nat mangle raw; do
  echo "-- table $t"
  iptables -t "$t" -S 2>/dev/null | grep -E '^-N MT_| MT_' || echo "(no MT_ chains)"
done
