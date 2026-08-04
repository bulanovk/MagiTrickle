# Stage 1: build stress-sni Go binary + generate domain list.
FROM golang:1.23-alpine AS stress-builder

RUN apk add --no-cache curl bash

WORKDIR /src
COPY stress-sni/ ./

# Use pre-generated domain list to avoid network dependency during build.
# Generate locally with: cd testenv/client/stress-sni && \
#   curl -fsSL https://github.com/runetfreedom/russia-blocked-geosite/releases/latest/download/category-ads-all.txt \
#   | sed 's/^domain://' | shuf -n 1000 > prebuilt-domains.txt
COPY stress-sni/prebuilt-domains.txt domains.txt
RUN go build -o stress-sni . && \
    mkdir -p /out && \
    cp stress-sni /out/stress-sni && \
    cp domains.txt /out/stress-domains.txt

# Stage 2: netshoot + test scripts + stress-sni binary.
# nicolaka/netshoot ships with curl, dig, openssl, iperf3, tcpdump
# and a dozen other networking utilities.
FROM nicolaka/netshoot:latest

# Test scripts (DNS-MITM / DoH+SNI / direct-TLS / direct-HTTP / direct-HTTP2)
# plus the shared reset helper sourced by every sniffer e2e test.
COPY scripts/                    /usr/local/bin/
RUN for f in /usr/local/bin/test-*.sh; do mv "$f" "${f%.sh}"; done
COPY --from=stress-builder /out/stress-sni           /usr/local/bin/stress-sni
COPY --from=stress-builder /out/stress-domains.txt   /usr/local/share/stress-domains.txt

# Runtime hook — points DNS at the host (which == router, since the
# router container uses network_mode: host) and exports convenience
# variables for the test scripts.
RUN cat > /usr/local/bin/rc.local <<'EOF'
#!/bin/bash
# Router container uses host networking, so it's reachable as the
# host's IP on the mt-net bridge — i.e. the default gateway.
ROUTER_IP=$(ip route show default | awk '{print $3; exit}')
[ -z "$ROUTER_IP" ] && ROUTER_IP=172.31.0.1
echo "MT-client: router=$ROUTER_IP"
echo "nameserver $ROUTER_IP" > /etc/resolv.conf
export ROUTER_IP WEBUI="http://$ROUTER_IP:8080"
# Make /usr/local/bin available in PATH for non-login shells.
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
EOF

# Wrap into a login-friendly entrypoint: source rc.local first, then
# exec an interactive bash. Sourcing keeps ROUTER_IP/WEBUI/PATH in the
# interactive shell's environment.
RUN cat > /usr/local/bin/start.sh <<'EOF'
#!/bin/bash
source /usr/local/bin/rc.local
exec bash "$@"
EOF

RUN chmod +x /usr/local/bin/rc.local /usr/local/bin/start.sh /usr/local/bin/test-*

CMD ["bash", "/usr/local/bin/start.sh"]
