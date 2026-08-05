#!/bin/bash
# Router entrypoint — host-net privileged container running magitrickled
# with SNI sniffer + DNS-MITM.
#
# 1. Load kernel modules (best-effort).
# 2. Wipe leftover iptables/ipset state.
# 3. Kill systemd-resolved if it occupies :53 (Ubuntu 24.04).
# 4. Switch iptables → legacy backend.
# 5. Detect egress iface, patch config.yaml, add MASQUERADE.
# 6. Probe sniffer modules, exec magitrickled.
set -e

modprobe xt_NFQUEUE      2>/dev/null || echo "[entry] xt_NFQUEUE load failed"
modprobe nfnetlink_queue 2>/dev/null || echo "[entry] nfnetlink_queue load failed"
modprobe ip_set          2>/dev/null || true
modprobe nf_conntrack    2>/dev/null || true
modprobe xt_connbytes    2>/dev/null || true

iptables -t mangle -D PREROUTING -j MT_SNI 2>/dev/null || true
iptables -t nat    -D PREROUTING -j MT_DNS  2>/dev/null || true
iptables -t mangle -F MT_SNI 2>/dev/null || true
iptables -t nat    -F MT_DNS 2>/dev/null || true
iptables -t mangle -X MT_SNI 2>/dev/null || true
iptables -t nat    -X MT_DNS 2>/dev/null || true
iptables -D FORWARD -j MT_d663a11a 2>/dev/null || true
iptables -t mangle -D PREROUTING -j MT_d663a11a 2>/dev/null || true
iptables -F MT_d663a11a 2>/dev/null || true
iptables -X MT_d663a11a 2>/dev/null || true
iptables -t mangle -F MT_d663a11a 2>/dev/null || true
iptables -t mangle -X MT_d663a11a 2>/dev/null || true

sysctl -w net.ipv4.ip_forward=1 >/dev/null

if [ -d /proc/1/root ]; then
  nsenter -t 1 -m systemctl stop systemd-resolved 2>/dev/null || true
  nsenter -t 1 -m systemctl mask systemd-resolved 2>/dev/null || true
  nsenter -t 1 -m pkill -9 -f systemd-resolve 2>/dev/null || true
fi
sleep 1
for i in 1 2 3 4 5; do
  if ! nsenter -t 1 -m ss -lnup 2>/dev/null | grep -qE '127\.0\.0\.5[34]:53'; then
    break
  fi
  sleep 1
done
if [ -f /etc/resolv.conf ] && grep -q '127.0.0.53' /etc/resolv.conf 2>/dev/null; then
  echo "nameserver 1.1.1.1" > /etc/resolv.conf || true
fi

update-alternatives --set iptables   /usr/sbin/iptables-legacy   >/dev/null 2>&1 || true
update-alternatives --set ip6tables  /usr/sbin/ip6tables-legacy  >/dev/null 2>&1 || true
hash iptables 2>/dev/null || true

# Detect egress interface and substitute __IFACE__ in config.
IF=$(ip -o -4 route show default | awk '{print $5}' | head -n1)
if [ -z "$IF" ]; then
  IF=$(ls /sys/class/net | grep -E '^e(n|th)' | sort | head -n1)
fi
[ -z "$IF" ] && IF=eth0
echo "[entry] iface=$IF"

sed "s/__IFACE__/$IF/" /var/lib/magitrickle/config.yaml > /tmp/config.yaml
iptables -t nat -A POSTROUTING -o "$IF" -j MASQUERADE || true

for m in xt_NFQUEUE nfnetlink_queue ip_set nf_conntrack; do
  if [ -d "/sys/module/$m" ]; then
    echo "[entry] module: $m OK"
  else
    echo "[entry] module: $m MISSING"
  fi
done

echo "[entry] starting magitrickled …"
exec /out/magitrickled -config /tmp/config.yaml
