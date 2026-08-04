#!/bin/bash
# Shared helpers for the sniffer e2e tests (test-tls, test-http, test-http2).
# Sourced from each script.

# Resolve the only enabled group on the stand (the testenv only has one).
get_test_group_id() {
  curl -fsS "${WEBUI}/api/v1/groups" \
    | python3 -c "import json,sys
g=[x for x in json.load(sys.stdin)['groups'] if x.get('enable')]
print(g[0]['id'] if g else '')"
}

# Return the IDs of all enabled groups, comma-separated, in YAML order.
# Used to flush every group's MT_SNI RETURN rule between test runs —
# the e2e tests share the stand with mt-stress (a wildcard group), so
# even targets that don't match a rule in the test group get attributed
# via the wildcard, and their IPs land in mt_a1b2c3d4_4. Skipping that
# group would leave the RETURN rule short-circuiting NFQUEUE.
get_all_enabled_group_ids() {
  curl -fsS "${WEBUI}/api/v1/groups" \
    | python3 -c "import json,sys
print(','.join(x['id'] for x in json.load(sys.stdin)['groups'] if x.get('enable')))"
}

# Disable then re-enable the named group so the MT_SNI RETURN rule and
# mt_<id>_4 ipset are torn down and rebuilt between runs.
#
# PutGroup/GroupFromReq overwrites name/interface/rules with whatever
# the request body contains — sending only {"enable":true} blanks them
# and the next Enable() call fails with "interface not found". So we
# GET the full group first, flip the enable bit, and PUT it back.
#
# Why this is needed: when the sniffer fires OnDomain for a domain
# that matches a group rule, the resolved IP is added to that group's
# ipset (timeout = additionalTTL, default 1h). Subsequent packets to
# that IP hit the MT_SNI RETURN rule and short-circuit NFQUEUE, so
# the sniffer never sees them again. The Disable() path removes the
# RETURN rule and destroys the ipset; the re-enable recreates them
# empty. Both sides of the cycle are required so production traffic
# routing via the group still works after the test completes.
_reset_one_group() {
  local group_id="$1"
  local base
  base=$(curl -fsS "${WEBUI}/api/v1/groups/${group_id}") \
    || { echo "reset_sniffer_state: GET ${group_id} failed" >&2; return 1; }

  local disabled enabled
  disabled=$(printf '%s' "$base" | python3 -c "import json,sys; d=json.load(sys.stdin); d['enable']=False; print(json.dumps(d))")
  enabled=$(printf '%s'  "$base" | python3 -c "import json,sys; d=json.load(sys.stdin); d['enable']=True;  print(json.dumps(d))")

  curl -fsS -X PUT -H "Content-Type: application/json" \
    -d "$disabled" "${WEBUI}/api/v1/groups/${group_id}" >/dev/null \
    || { echo "reset_sniffer_state: PUT disable ${group_id} failed" >&2; return 1; }
  sleep 0.4
  curl -fsS -X PUT -H "Content-Type: application/json" \
    -d "$enabled" "${WEBUI}/api/v1/groups/${group_id}" >/dev/null \
    || { echo "reset_sniffer_state: PUT enable ${group_id} failed" >&2; return 1; }
  sleep 0.4
}

# Reset the MT_SNI state for ALL enabled groups, not just the test
# group — see get_all_enabled_group_ids for the rationale.
reset_sniffer_state() {
  local ids
  ids=$(get_all_enabled_group_ids) || { echo "reset_sniffer_state: list groups failed" >&2; return 1; }
  [ -z "$ids" ] && { echo "reset_sniffer_state: no enabled groups" >&2; return 1; }

  local id
  IFS=',' read -r -a _ids <<< "$ids"
  for id in "${_ids[@]}"; do
    _reset_one_group "$id" || return 1
  done
}