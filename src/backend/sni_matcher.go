package magitrickle

import (
	"net"
	"time"

	"magitrickle/sniffer"
	"magitrickle/utils/netfilterTools"

	"github.com/rs/zerolog/log"
)

// newSNIMatcher returns a sniffer.Hooks whose OnDomain closure feeds an
// extracted (domain, dstIP) tuple into the same rule-matching pipeline
// used by the DNS-MITM path. On a match, the destination IP is added
// to the matching RuleSet's ipset with the configured additional TTL.
//
// The closure is intentionally simple — the heavy lifting (matching,
// ipset CRUD, recordsCache bookkeeping) is shared with dns.go. We only
// provide the bridge between the sniffer's protocol-aware output and
// the existing rule sets.
func newSNIMatcher(a *App) sniffer.Hooks {
	return sniffer.Hooks{
		OnDomain: func(domain string, dstIP []byte, protocol sniffer.Protocol) {
			if domain == "" || len(dstIP) == 0 {
				return
			}
			ip := net.IP(dstIP)
			isV4 := ip.To4() != nil

			ttl := a.config.SNISniffer.AdditionalTTL
			if ttl <= 0 {
				ttl = time.Hour
			}

			matched := false
			for _, rs := range a.ruleSetSnapshot() {
				if !rs.Enabled() || !rs.ConfiguredEnabled() {
					continue
				}
				for _, rule := range rs.RuleModels() {
					if !rule.IsMatch(domain) {
						continue
					}
					matched = true
					var err error
					if isV4 {
						v4 := ip.To4()
						subnet := ipv4SubnetFromBytes(v4)
						err = rs.AddIPv4Subnet(subnet, ipsetTimeout(ttl))
					} else {
						v6 := ip.To16()
						subnet := ipv6SubnetFromBytes(v6)
						err = rs.AddIPv6Subnet(subnet, ipsetTimeout(ttl))
					}
					if err != nil {
						log.Warn().Err(err).
							Str("domain", domain).
							Str("ip", ip.String()).
							Str("protocol", string(protocol)).
							Msg("SNI: failed to add IP to rule set")
						continue
					}
					// Record the observation so DNS-handling paths can
					// later detect disagreement (SNI says X, DNS says Y).
					a.recordsCache.ObserveSNI(ip.String(), domain)
					log.Debug().
						Str("domain", domain).
						Str("ip", ip.String()).
						Str("protocol", string(protocol)).
						Str("rule_set", rs.DisplayName()).
						Msg("SNI sniffed")
					break // first matching rule is enough for this rule set
				}
			}
			if !matched {
				log.Debug().
					Str("domain", domain).
					Str("ip", ip.String()).
					Str("protocol", string(protocol)).
					Msg("SNI extracted but no rule matched")
			}
		},
	}
}

// ipv4SubnetFromBytes wraps a 4-byte slice into a /32 IPv4Subnet.
func ipv4SubnetFromBytes(b []byte) netfilterTools.IPv4Subnet {
	var addr [4]byte
	copy(addr[:], b)
	return netfilterTools.IPv4Subnet{Address: addr, CIDR: 32}
}

// ipv6SubnetFromBytes wraps a 16-byte slice into a /128 IPv6Subnet.
func ipv6SubnetFromBytes(b []byte) netfilterTools.IPv6Subnet {
	var addr [16]byte
	copy(addr[:], b)
	return netfilterTools.IPv6Subnet{Address: addr, CIDR: 128}
}

// ipsetTimeout converts a time.Duration into the IPSetTimeout
// (uint32-pointer) expected by netfilterTools.Add*Subnet. Zero or
// negative durations fall back to the package's notion of "no expiry".
func ipsetTimeout(d time.Duration) netfilterTools.IPSetTimeout {
	if d <= 0 {
		return nil
	}
	secs := uint32(d.Seconds())
	return &secs
}