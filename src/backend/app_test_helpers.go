//go:build integration

package magitrickle

import (
	"magitrickle/sniffer"
	"magitrickle/utils/iptables"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"
)

// InstallTestDeps wires the collaborators needed by the SNI-sniffer glue
// without running the full App.Start() lifecycle (which would bind DNS-proxy
// sockets and require kernel routes that may not be present in the test
// environment). It mirrors the minimal subset of start.go that
// RuleSet.Enable() depends on: registering built-in chains (FORWARD,
// PREROUTING) so that subsequent delete operations find a non-empty chain
// registry. It exists to support tests/sniffer_integ.
func InstallTestDeps(a *App, nf *netfilterTools.Helper, cache *recordsCache.Records) {
	a.nfHelper = nf
	a.recordsCache = cache
	a.enabled.Store(true)

	for _, ipt := range []*iptables.IPTables{nf.IPTables4, nf.IPTables6} {
		if ipt == nil {
			continue
		}
		_ = ipt.RegisterChainPatch("filter", "FORWARD")
		_ = ipt.RegisterChainPatch(nf.MarkTable, "PREROUTING")
		_ = ipt.RegisterChainPatch("nat", "PREROUTING")
		_ = ipt.RegisterChainPatch("nat", "POSTROUTING")
	}
}

// NewSNIMatcherForTesting exposes newSNIMatcher (unexported) to external test
// packages. Stripped from non-integration builds via the file's build tag.
func NewSNIMatcherForTesting(a *App) sniffer.Hooks {
	return newSNIMatcher(a)
}
