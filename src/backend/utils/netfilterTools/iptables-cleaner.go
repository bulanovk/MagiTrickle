package netfilterTools

import (
	"errors"
	"fmt"
	"strings"

	"magitrickle/utils/iptables"
)

func (nh *Helper) cleanIPTables(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	jumpToChainPrefix := "-j " + nh.ChainPrefix

	exists, err := ipt.GetCurrentRules()
	if err != nil {
		return fmt.Errorf("listing chains error: %w", err)
	}

	// Chains (and their inbound jumps) owned by SNIRules are managed
	// outside the normal group-link lifecycle and live in mangle. They
	// are installed once per session by sniRules.Enable() and must
	// survive the start-of-day clean so the sniffer stays wired.
	sniChainName := nh.ChainPrefix + "SNI"
	sniJumpTarget := "-j " + sniChainName
	isSNIManaged := func(chain string) bool {
		return chain == sniChainName
	}
	jumpTargetsSNIManaged := func(rule interface{ Contains(string) bool }) bool {
		return rule.Contains(sniJumpTarget)
	}

	for table, chains := range exists {
		chainListToDelete := make([]string, 0)

		for chain, rules := range chains {
			if strings.HasPrefix(chain, nh.ChainPrefix) {
				if !isSNIManaged(chain) {
					chainListToDelete = append(chainListToDelete, chain)
				}
				continue
			}

			for _, r := range rules {
				if !r.Contains(jumpToChainPrefix) {
					continue
				}
				if jumpTargetsSNIManaged(r) {
					// -j MT_SNI is owned by SNIRules and must remain
					// in PREROUTING for the sniffer to receive packets.
					continue
				}

				err = ipt.Delete(table, chain, r.Args()...)
				if errors.Is(err, iptables.ErrChainNotInitialized) {
					err = ipt.RegisterChainPatch(table, chain)
					if err != nil {
						return fmt.Errorf("chain register error: %w", err)
					}
					err = ipt.Delete(table, chain, r.Args()...)
				}
				if err != nil {
					return fmt.Errorf("rule deletion error: %w", err)
				}
			}
		}

		for _, chain := range chainListToDelete {
			err = ipt.RegisterChainDelete(table, chain)
			if err != nil {
				return fmt.Errorf("deleting chain error: %w", err)
			}
		}
	}

	err = ipt.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit iptables rules: %w", err)
	}
	return nil
}

func (nh *Helper) CleanIPTables() error {
	var errs []error
	errs = append(errs, nh.cleanIPTables(nh.IPTables4))
	errs = append(errs, nh.cleanIPTables(nh.IPTables6))
	return errors.Join(errs...)
}
