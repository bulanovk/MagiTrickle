//go:build testing

package netfilterTools

import (
	"strings"
	"testing"

	"magitrickle/utils/iptables"
)

// helper to build a SNIRules wired to a fresh FakeIPTables instance.
func newTestSNIRules(t *testing.T, proto iptables.Protocol, allowedPorts []uint16) (*SNIRules, *iptables.FakeIPTables) {
	t.Helper()
	fake := iptables.NewFakeIPTables(proto)
	nh := &Helper{
		ChainPrefix: "MT_",
		IpsetPrefix: "mt_",
		IPTables4:   nil,
		IPTables6:   nil,
	}
	if proto == iptables.ProtocolIPv4 {
		nh.IPTables4 = iptables.NewIPTables(fake)
	} else {
		nh.IPTables6 = iptables.NewIPTables(fake)
	}
	return nh.SNIRules(0, allowedPorts), fake
}

// findRule returns the first NFQUEUE rule in mangle/<chain>.
func findNFQUEERule(t *testing.T, fake *iptables.FakeIPTables, chain string) []string {
	t.Helper()
	rules := fake.GetRules("mangle", chain)
	if len(rules) == 0 {
		t.Fatalf("no rules found in mangle/%s", chain)
	}
	for _, r := range rules {
		for _, tok := range r {
			if tok == "NFQUEUE" {
				return r
			}
		}
	}
	t.Fatalf("no NFQUEUE rule in mangle/%s; rules=%v", chain, rules)
	return nil
}

// rulesString renders a rule as a single string for substring checks.
func rulesString(rule []string) string { return strings.Join(rule, " ") }

// TestSNIRule_QueuesAllowedPorts ensures the NFQUEUE rule scopes
// interception to the configured allowedPorts via -m multiport.
func TestSNIRule_QueuesAllowedPorts(t *testing.T) {
	r, fake := newTestSNIRules(t, iptables.ProtocolIPv4, []uint16{443, 80, 8443})
	if err := r.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	defer r.Disable()

	rule := findNFQUEERule(t, fake, "MT_SNI")
	rs := rulesString(rule)
	if !strings.Contains(rs, "-p tcp") {
		t.Errorf("NFQUEUE rule missing `-p tcp`; got: %s", rs)
	}
	if !strings.Contains(rs, "--dports 443,80,8443") {
		t.Errorf("NFQUEUE rule should use multiport for configured ports; got: %s", rs)
	}
	if strings.Contains(rs, " --dport ") {
		t.Errorf("NFQUEUE rule should not use single `--dport` form when multiport applies; got: %s", rs)
	}
}

// TestSNIRule_AllTCPWhenAllowedPortsEmpty ensures that with no port
// allow-list the rule matches all TCP (mirrors sniffer.portAllowed).
func TestSNIRule_AllTCPWhenAllowedPortsEmpty(t *testing.T) {
	r, fake := newTestSNIRules(t, iptables.ProtocolIPv4, nil)
	if err := r.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	defer r.Disable()

	rule := findNFQUEERule(t, fake, "MT_SNI")
	rs := rulesString(rule)
	if !strings.Contains(rs, "-p tcp") {
		t.Errorf("NFQUEUE rule missing `-p tcp`; got: %s", rs)
	}
	if strings.Contains(rs, "multiport") || strings.Contains(rs, "--dport") {
		t.Errorf("NFQUEUE rule should not carry any port match when allowedPorts is empty; got: %s", rs)
	}
}

// TestSNIRule_DirectionQueuesAllTraffic documents that the rule no
// longer filters to ORIGINAL direction only — conntrack does not
// reliably tag post-handshake segments as ORIGINAL under MASQUERADE
// on Linux 6.8, so the broader "any TCP to the allowed ports" match
// is used. The callback drops REPLY-direction packets (ServerHello,
// cert fragments) at the parser level.
func TestSNIRule_DirectionQueuesAllTraffic(t *testing.T) {
	r, fake := newTestSNIRules(t, iptables.ProtocolIPv4, []uint16{443})
	if err := r.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	defer r.Disable()

	rule := findNFQUEERule(t, fake, "MT_SNI")
	rs := rulesString(rule)
	if strings.Contains(rs, "--ctdir") {
		t.Errorf("NFQUEUE rule should no longer carry --ctdir ORIGINAL (kernel 6.8 conntrack under MASQUERADE); got: %s", rs)
	}
	if !strings.Contains(rs, "-j NFQUEUE") {
		t.Errorf("NFQUEUE rule missing -j NFQUEUE; got: %s", rs)
	}
}

// TestSNIRule_GroupReturn verifies that AddGroupReturn inserts RETURN
// rules before the NFQUEUE fallback, and DelGroupReturn removes them.
func TestSNIRule_GroupReturn(t *testing.T) {
	r, fake := newTestSNIRules(t, iptables.ProtocolIPv4, []uint16{443})
	if err := r.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	defer r.Disable()

	// Add a group RETURN rule.
	if err := r.addGroupReturn(r.nh.IPTables4, "mt_testgroup_4"); err != nil {
		t.Fatalf("addGroupReturn: %v", err)
	}

	rules := fake.GetRules("mangle", "MT_SNI")
	if len(rules) < 2 {
		t.Fatalf("expected at least 2 rules (RETURN + NFQUEUE), got %d: %v", len(rules), rules)
	}

	// First rule should be the RETURN.
	if !containsToken(rules[0], "RETURN") {
		t.Errorf("first rule should be RETURN, got: %v", rules[0])
	}
	if !containsToken(rules[0], "mt_testgroup_4") {
		t.Errorf("RETURN rule missing ipset name, got: %v", rules[0])
	}

	// Last rule should be NFQUEUE.
	if !containsToken(rules[len(rules)-1], "NFQUEUE") {
		t.Errorf("last rule should be NFQUEUE, got: %v", rules[len(rules)-1])
	}

	// Delete the group RETURN rule.
	if err := r.delGroupReturn(r.nh.IPTables4, "mt_testgroup_4"); err != nil {
		t.Fatalf("delGroupReturn: %v", err)
	}

	rules = fake.GetRules("mangle", "MT_SNI")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after delete, got %d: %v", len(rules), rules)
	}
	if !containsToken(rules[0], "NFQUEUE") {
		t.Errorf("remaining rule should be NFQUEUE, got: %v", rules[0])
	}
}

func containsToken(rule []string, token string) bool {
	for _, t := range rule {
		if t == token {
			return true
		}
	}
	return false
}

// TestSNIRule_IPv6_QueuesAllowedPorts mirrors the IPv4 check for IPv6.
func TestSNIRule_IPv6_QueuesAllowedPorts(t *testing.T) {
	r, fake := newTestSNIRules(t, iptables.ProtocolIPv6, []uint16{443, 80, 8443})
	if err := r.Enable(); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	defer r.Disable()

	rule := findNFQUEERule(t, fake, "MT_SNI")
	rs := rulesString(rule)
	if !strings.Contains(rs, "-p tcp") {
		t.Errorf("IPv6 NFQUEUE rule missing `-p tcp`; got: %s", rs)
	}
	if !strings.Contains(rs, "--dports 443,80,8443") {
		t.Errorf("IPv6 NFQUEUE rule should use multiport for configured ports; got: %s", rs)
	}
}
