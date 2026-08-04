//go:build integration && linux

// Package sniffer_integ end-to-end-verifies the SNI matcher glue:
//
//   1. Construct a minimal MagiTrickle App via New().
//   2. Inject nfHelper + recordsCache via the integration-only helper
//      magitrickle.InstallTestDeps (avoids running the full Start() lifecycle).
//   3. Add a group with a domain rule and call Enable() — this creates a
//      real bitmap:ip ipset via netlink.
//   4. Invoke newSNIMatcher.OnDomain with (testDomain, 127.0.0.1, tls).
//   5. Verify the dst IP landed in the group's ipset via netlink.IpsetList.
//   6. Verify the recordsCache saw the observation.
//
// Run with:
//
//	go test ./tests/sniffer_integ/... -tags=integration -v
//
// Will t.Skip() automatically on Linux without root or without ip_set
// loaded.
package sniffer_integ

import (
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	magitrickle "magitrickle"
	"magitrickle/models"
	"magitrickle/sniffer"
	"magitrickle/utils/intID"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"

	"github.com/vishvananda/netlink"
)

const (
	testIpsetPrefix = "mt_e2e_"
	testChainPrefix = "MT_E2E_"
	testIface       = "lo"
	testDomain      = "e2e.test"
	testIP          = "127.0.0.1"
)

func moduleLoaded(mod string) bool {
	if _, err := os.Stat("/sys/module/" + mod); err == nil {
		return true
	}
	if out, err := os.ReadFile("/proc/modules"); err == nil {
		return strings.Contains(string(out), " "+mod+" ")
	}
	return false
}

func kernelReady(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("integration test requires linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root (ipset netlink)")
	}
	if !moduleLoaded("ip_set") {
		t.Skip("integration test requires ip_set kernel module")
	}
}

func mustAppWithDeps(t *testing.T) *magitrickle.App {
	t.Helper()
	nf, err := netfilterTools.New(testChainPrefix, testIpsetPrefix, false, false, 0)
	if err != nil {
		t.Fatalf("netfilterTools.New: %v", err)
	}
	cache := recordsCache.New()

	a := magitrickle.New()
	cfg := a.SNISnifferConfig()
	if cfg.AdditionalTTL == 0 {
		cfg.AdditionalTTL = time.Hour
		_ = a.SetSNISnifferConfig(cfg, false)
	}
	magitrickle.InstallTestDeps(a, nf, cache)
	return a
}

func TestSNIMatcher_AddsIPToIpset(t *testing.T) {
	kernelReady(t)

	a := mustAppWithDeps(t)

	ruleID := intID.ID{0xCA, 0xFE, 0xBA, 0xBE}
	groupID := intID.ID{0xDE, 0xAD, 0xBE, 0xEF}
	g := &models.Group{
		ID:        groupID,
		Name:      "e2e-sniffer",
		Interface: testIface,
		Enable:    true,
		Rules: []*models.Rule{{
			ID:     ruleID,
			Type:   models.RuleTypeDomain,
			Rule:   testDomain,
			Enable: true,
		}},
	}
	if err := a.AddGroup(g); err != nil {
		t.Fatalf("AddGroup: %v", err)
	}

	rss := a.UserGroups()
	if len(rss) == 0 {
		t.Fatal("expected at least one RuleSet after AddGroup")
	}
	for _, rs := range rss {
		if err := rs.Enable(); err != nil {
			t.Fatalf("RuleSet.Enable: %v", err)
		}
		t.Cleanup(func() { _ = rs.Disable() })
	}

	// Locate the v4 ipset that Enable() created.
	all, err := netlink.IpsetListAll()
	if err != nil {
		t.Fatalf("netlink.IpsetListAll: %v", err)
	}
	var v4Name string
	for _, r := range all {
		if r.Family == netlink.FAMILY_V4 && strings.HasPrefix(r.SetName, testIpsetPrefix) {
			v4Name = r.SetName
			break
		}
	}
	if v4Name == "" {
		t.Fatalf("no v4 ipset found with prefix %q after Enable()", testIpsetPrefix)
	}

	// Verify the set is empty before our synthetic sniff call.
	ip := net.ParseIP(testIP).To4()
	if ip == nil {
		t.Fatalf("parse %q", testIP)
	}
	if containsIP(t, v4Name, ip) {
		t.Fatalf("ipset %q already contained %s before OnDomain", v4Name, testIP)
	}

	// Invoke the matcher closure.
	hooks := magitrickle.NewSNIMatcherForTesting(a)
	hooks.OnDomain(testDomain, ip, sniffer.ProtocolTLS)

	// Verify the dst IP landed in the ipset.
	if !containsIP(t, v4Name, ip) {
		t.Fatalf("ipset %q does not contain %s after OnDomain", v4Name, testIP)
	}

	// Also verify the recordsCache saw the observation via the public
	// SNISnifferRecent endpoint.
	obs, err := a.SNISnifferRecent(10)
	if err != nil {
		t.Fatalf("SNISnifferRecent: %v", err)
	}
	if len(obs) == 0 {
		t.Fatalf("recordsCache has no SNI observations after OnDomain")
	}
	found := false
	for _, o := range obs {
		if o.IP == testIP && o.Domain == testDomain {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("recordsCache did not observe (%s, %s); got %+v", testIP, testDomain, obs)
	}
}

func containsIP(t *testing.T, name string, ip net.IP) bool {
	t.Helper()
	res, err := netlink.IpsetList(name)
	if err != nil {
		t.Fatalf("IpsetList %q: %v", name, err)
	}
	for _, e := range res.Entries {
		if e.IP.Equal(ip) {
			return true
		}
	}
	return false
}
