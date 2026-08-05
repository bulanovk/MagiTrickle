# MagiTrickle test stand

Two-container Docker Compose environment for exercising MagiTrickle
end-to-end without touching a real router. One stand covers both the
DNS-MITM path and the SNI sniffer path.

## Topology

```
                ┌─────────────────────────────────────┐
                │              host (Docker)         │
                │                                     │
                │   ┌──────────┐      ┌──────────┐    │
   mt-net  ◄────┤   │  router  │      │  client  │    │
                │   │  priv.   │      │ netshoot │    │
                │   │ magitrick│      │ curl/dig │    │
                │   │  led     │      │ openssl  │    │
                │   │  +SNI    │      │ stress   │    │
                │   └─────┬────┘      └────┬─────┘    │
                │         │   host netns    │          │
                │         ▼               bridge      │
                │   0.0.0.0:53+443+8080  (mt-net)     │
                │         │               │          │
                │         ▼               ▼          │
                │     host internet                  │
                └─────────────────────────────────────┘
```

- **router** — privileged container running with `network_mode: host` so
  the kernel's `nfnetlink_queue` subsystem (which lives in `init_net`) is
  reachable. With a private bridge, the container's netns lacks that
  subsystem and the sniffer's netlink bind fails with `ENODEV`. The router
  binds `0.0.0.0:53` (DNS-MITM), `:443` (HTTPS for SNI sniffing), and
  `:8080` (HTTP API / WebUI).
- **client** — `nicolaka/netshoot` on the `mt-net` bridge. The default
  gateway on that bridge is the host's IP, which is the same address the
  host-network router listens on, so the client transparently reaches
  the router via DNS and HTTPS without any port mapping.

## Build & run

```bash
cd testenv
docker compose build                  # builds both router (e2e) + client images
docker compose up -d                  # router starts first, client depends_on healthy
docker compose exec client bash
  client$ test-dns     # DNS-MITM scenario
  client$ test-doh     # DoH / HTTPS scenario (SNI path)
  client$ test-tls     # direct HTTPS to known sniffer targets (TLS ClientHello SNI)
  client$ test-http    # direct HTTP/1.1 to sniffer targets (Host header)
  client$ test-http2   # direct HTTP/2 h2c to sniffer targets (:authority)
  client$ stress-sni -mode burst -workers 20 -duration 30s
docker compose exec router dump-sni        # sniffer state
docker compose exec router ipset-inspect   # mt_* ipsets + MT_* chains
```

WebUI: open <http://127.0.0.1:8080> (port 8080 is published from the
host-network router).

External HTTPS from outside Docker:

```bash
curl -k --resolve example.com:443:127.0.0.1 https://example.com/
```

The router's NFQUEUE hook catches the ClientHello, parses `SNI=example.com`,
and adds the resolved IP to `mt_d663a11a_4` via the sniffer path.

## Scenarios

### DNS-MITM (`test-dns.sh`)

Client `dig`s domains directly at the router IP; magitrickled's DNS proxy
answers and adds the IP to the matching group's ipset on every A/AAAA
response. **No kernel modules required.**

### DoH / SNI sniffer (`test-doh.sh`)

Client resolves via `curl --doh-url` (DNS bypasses the proxy), then opens
a TLS connection to `example.com:443`. The SNI sniffer catches the
ClientHello, parses `SNI=example.com`, and adds the resolved IP via the
NFQUEUE path.

### Direct TLS (`test-tls.sh`)

Plain HTTPS via `curl --resolve` so the client always hits the router's
HTTPS port regardless of DNS path. Verifies the sniffer parses the
TLS ClientHello `SNI` extension. Uses external DNS so the resolved
IP is not pre-populated in the wildcard-resolved ipset.

### Direct HTTP/1.1 (`test-http.sh`)

Plain HTTP via `curl --resolve` on port 80. Verifies the sniffer
parses the HTTP/1.1 `Host` header from real traffic flowing through
the NFQUEUE hook. Uses external DNS so the resolved IP is not
pre-populated in the wildcard-resolved ipset.

### Direct HTTP/2 (`test-http2.sh`)

Plain HTTP/2 (`h2c`) via a Python helper that sends the connection
preface + a HEADERS frame with `:authority` to port 80. The server
is allowed to reset the connection — only the first packet (which
the sniffer sees through NFQUEUE) matters. Same external-DNS trick
to bypass the wildcard ipset.

### Stress (`stress-sni`)

TLS handshake load generator with built-in domain list
([russia-blocked-geosite](https://github.com/runetfreedom/russia-blocked-geosite)).
Results are written to `/tmp/stress-report.json` (JSON) and printed as a
text summary.

## Enabling SNI sniffer on this host

The NFQUEUE path requires host kernel modules: `xt_NFQUEUE` +
`nfnetlink_queue` + `nf_conntrack` + `xt_connbytes`. The probe in
`src/backend/sniffer/probe.go` checks `/sys/module/xt_NFQUEUE` and
disables the sniffer if absent.

```bash
# Debian / PVE host — install DKMS module package
apt-get install xtables-addons-dkms
modprobe xt_NFQUEUE nfnetlink_queue xt_connbytes
ls /sys/module/xt_NFQUEUE   # must exist
docker compose restart router
docker compose exec router dump-sni   # look for "module: xt_NFQUEUE OK"
```

On Keenetic / OpenWrt the modules come from the
"Kernel modules for Netfilter" NDMS component (or `kmod-xt-nfqueue` on
OpenWrt) — `modprobe xt_NFQUEUE nfnetlink_queue xt_connbytes` brings them
up.

## Files

| Path | Purpose |
|---|---|
| `docker-compose.yml` | one router + one client |
| `router/entrypoint.sh` | modprobe + iptables-legacy + systemd-resolved cleanup + MASQUERADE + exec |
| `router/config.yaml` | sniffer config + mt-router group with example/cloudflare/mozilla/wildcard |
| `router/dump-sni.sh` | sniffer state (modules, ipsets, chains, stats) |
| `router/ipset-inspect.sh` | mt_* ipsets + MT_* chains |
| `client/Dockerfile` | nicolaka/netshoot + stress-sni + 5 test scripts |
| `client/scripts/test-dns.sh` | DNS-MITM scenario |
| `client/scripts/test-doh.sh` | DoH / HTTPS scenario |
| `client/scripts/test-tls.sh` | direct HTTPS to sniffer targets (TLS) |
| `client/scripts/test-http.sh` | direct HTTP/1.1 to sniffer targets |
| `client/scripts/test-http2.sh` | direct HTTP/2 h2c to sniffer targets |
| `client/stress-sni/` | stress tool source |

## Customising

- Change `groups[].rules[]` in `router/config.yaml` to match different
  domains.
- Change `sniSniffer.allowedPorts` to widen the port allow-list.
- To disable the SNI path entirely: set `sniSniffer.enabled: false`.
