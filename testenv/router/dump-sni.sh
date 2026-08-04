#!/bin/bash
# Dump sniffer state — modules probed, ipsets, MT chains, JSON stats.
echo "== kernel modules =="
for m in xt_NFQUEUE nfnetlink_queue ip_set nf_conntrack xt_connbytes; do
    if [ -d /sys/module/$m ]; then
        echo "  $m: OK"
    else
        echo "  $m: MISSING"
    fi
done
echo
echo "== mt_* ipsets =="
ipset list -name | grep ^mt_ | while read s; do
    echo "----- $s -----"
    ipset list "$s" 2>&1 | head -20
done
echo
echo "== MT_* chains =="
iptables -S 2>/dev/null | grep -E 'MT_|MASQUERADE' | head -20
echo
echo "== nfqueue hook =="
iptables -t mangle -L PREROUTING -n 2>&1 | head -20
echo
echo "== sniffer stats =="
curl -fsS http://127.0.0.1:8080/api/v1/sniffer/stats 2>&1 | head -c 800
echo
echo
echo "== sniffer recent =="
curl -fsS "http://127.0.0.1:8080/api/v1/sniffer/recent?limit=20" 2>&1 | head -c 1200
echo
