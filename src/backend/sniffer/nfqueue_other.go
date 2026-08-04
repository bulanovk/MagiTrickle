//go:build !linux

package sniffer

// newCGoSniffer and newFlorianlSniffer return a NoOpSniffer on non-Linux
// platforms. NFQUEUE is a Linux-only netfilter feature.
func newCGoSniffer(_ Config) *NoOpSniffer {
	return &NoOpSniffer{}
}

func newFlorianlSniffer(_ Config) *NoOpSniffer {
	return &NoOpSniffer{}
}
