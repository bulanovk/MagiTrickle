#!/bin/bash
# Fetch a category from v2fly/domain-list-community, shuffle, trim to N.
#
# Upstream: https://github.com/v2fly/domain-list-community
# We pull the latest release's dlc.dat_plain.yml (resolved YAML, ~3.5 MB)
# and extract a single category. Each entry in that YAML looks like:
#
#   - name: "category-ads-all"
#     length: 906
#     rules:
#       - "domain:1rx.io:@ads"
#       - "domain:51.la"
#
# Rules may carry an attribute tag (":@ads" etc.) — we strip both the
# "domain:" prefix and any trailing ":@tag" so the output is a flat
# list of bare domains, one per line.
#
# Usage:   ./gen-domains.sh [out-file] [category]
# Defaults: out=domains.txt, category=category-ads-all
# Env:
#   GEN_DOMAINS_COUNT=N        number of domains to keep (default 1000)
set -euo pipefail

COUNT="${GEN_DOMAINS_COUNT:-1000}"
CATEGORY="${2:-category-ads-all}"
OUT="${1:-domains.txt}"
REPO="v2fly/domain-list-community"
RELEASE_API="https://api.github.com/repos/${REPO}/releases/latest"
ASSET_NAME="dlc.dat_plain.yml"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "[gen-domains] resolving latest ${REPO} release"
ASSET_URL=$(curl -fsSL --connect-timeout 10 --max-time 30 "$RELEASE_API" \
  | python3 -c "import json,sys; r=json.load(sys.stdin); print(next(a['browser_download_url'] for a in r['assets'] if a['name']=='${ASSET_NAME}'))")

echo "[gen-domains] fetching ${ASSET_URL}"
curl -fsSL --connect-timeout 10 --max-time 60 "$ASSET_URL" -o "$TMP"

echo "[gen-domains] extracting category=${CATEGORY}, keeping first ${COUNT}"
python3 - "$TMP" "$CATEGORY" "$COUNT" "$OUT" <<'PY'
import sys, re, random
src, target, count, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
with open(src) as f:
    # Tiny streaming parser: we only care about the entry whose
    # `name:` field equals the target. Each rule we want to keep
    # starts with `      - "domain:`. Anything else is skipped.
    in_target = False
    depth = 0
    rules = []
    rule_re = re.compile(r'^\s*-\s*"(domain:[^"]+)"\s*$')
    for line in f:
        stripped = line.lstrip()
        if not in_target:
            if stripped.startswith('- name:'):
                in_target = stripped.rstrip() == f'- name: "{target}"'
            continue
        # We are inside the target entry. Track indentation to know
        # when we leave the `rules:` block (back to entry-list level).
        if stripped.startswith('- name:'):
            break  # next list entry
        m = rule_re.match(line)
        if m:
            rules.append(m.group(1))
if not rules:
    sys.exit(f"[gen-domains] category {target!r} not found or empty in {src}")
random.SystemRandom().shuffle(rules)
strip_re = re.compile(r'^domain:([^:]+)(?::@\w+)?$')
with open(out, 'w') as g:
    kept = 0
    for r in rules:
        if kept >= count:
            break
        m = strip_re.match(r)
        if m:
            g.write(m.group(1) + '\n')
            kept += 1
print(f"[gen-domains] wrote {kept} domains from category={target} to {out}")
PY
