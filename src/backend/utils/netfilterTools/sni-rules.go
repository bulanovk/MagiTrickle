package netfilterTools

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"magitrickle/utils/iptables"
)

// SNIRules owns the MT_SNI chain installed in the mangle table. The
// chain's final rule sends unmatched TCP flows to NFQUEUE for the SNI
// sniffer. Each active group inserts a RETURN rule ahead of the NFQUEUE
// fallback: packets whose dst IP matches a group ipset exit the chain
// immediately and never reach the userspace sniffer.
//
// Chain layout (example with two groups):
//
//	-m set --match-set mt_<group1>_4 dst -j RETURN
//	-m set --match-set mt_<group2>_4 dst -j RETURN
//	-p tcp -j NFQUEUE --queue-num N
//
// Every TCP flow reaches the userspace sniffer — there is no port
// allow-list; the parser decides per payload whether it is TLS/HTTP.
//
// The RETURN rules are managed via AddGroupReturn/DelGroupReturn so
// the chain stays in sync with active groups regardless of whether the
// group was enabled at startup or later via the API.
type SNIRules struct {
	enabled atomic.Bool
	locker  sync.Mutex

	nh       *Helper
	queueNum uint16
}

func (r *SNIRules) chainName() string { return r.nh.ChainPrefix + "SNI" }

// insertRules creates the MT_SNI chain with the NFQUEUE fallback rule
// and links it into mangle/PREROUTING. Group RETURN rules are added
// separately via AddGroupReturn when each group enables.
func (r *SNIRules) insertRules(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}

	chain := r.chainName()
	table := "mangle"

	if err := ipt.RegisterChainPatch(table, "PREROUTING"); err != nil {
		return fmt.Errorf("failed to register %s/PREROUTING: %w", table, err)
	}

	if err := ipt.RegisterChainOverride(table, chain); err != nil {
		return fmt.Errorf("failed to create chain %s: %w", chain, err)
	}

	// Final fallback: flows not matched by any group RETURN rule land
	// here for SNI sniffing.
	//
	// NOTE: earlier revisions added `-m conntrack --ctdir ORIGINAL` to
	// filter down to initiator→responder packets only. That relied on
	// the kernel correctly marking post-handshake data segments as
	// ORIGINAL. Under MASQUERADE on Linux 6.8 the conntrack match
	// misses a large fraction of ClientHello segments, so this filter
	// was dropped: the extra traffic in REPLY direction (ServerHello
	// + cert fragments) is harmless — the parser only acts on
	// outbound ClientHello — and the queue throughput is still well
	// within MaxQueueLen for realistic workloads.
	// --queue-bypass intentionally omitted.
	// On kernel ≥6.8 the bypass flag causes the queue to skip all
	// packets even when a userspace listener is connected, which
	// means the sniffer would never see traffic. Without bypass
	// the kernel delivers packets normally and the Go nfqueue
	// library feeds them to the callback. If the daemon crashes
	// the MT_SNI chain is torn down during shutdown, so there is
	// no permanent-dropping window.
	args := []string{"-p", "tcp", "-j", "NFQUEUE", "--queue-num", strconv.Itoa(int(r.queueNum))}
	if err := ipt.Append(table, chain, args...); err != nil {
		return fmt.Errorf("failed to append NFQUEUE rule to %s: %w", chain, err)
	}

	// PREROUTING → MT_SNI. Insert at position 1 so we run before the
	// existing MT_* group jumps (which mark traffic for routing).
	if err := ipt.Insert(table, "PREROUTING", 1, "-j", chain); err != nil {
		return fmt.Errorf("failed to link %s into %s/PREROUTING: %w", chain, table, err)
	}

	if err := ipt.Commit(); err != nil {
		return fmt.Errorf("failed to commit iptables rules: %w", err)
	}
	return nil
}

// addGroupReturn inserts a RETURN rule at position 1 in MT_SNI for one
// group ipset. Packets whose dst IP is in this ipset exit the chain
// immediately — they are already attributed and the sniffer does not
// need to inspect them.
func (r *SNIRules) addGroupReturn(ipt *iptables.IPTables, ipsetName string) error {
	if ipt == nil {
		return nil
	}
	chain := r.chainName()
	table := "mangle"

	if err := ipt.Insert(table, chain, 1,
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "RETURN",
	); err != nil {
		return fmt.Errorf("failed to insert RETURN rule for %s: %w", ipsetName, err)
	}
	if err := ipt.Commit(); err != nil {
		return fmt.Errorf("failed to commit RETURN rule for %s: %w", ipsetName, err)
	}
	return nil
}

// delGroupReturn removes the RETURN rule for one group ipset from MT_SNI.
func (r *SNIRules) delGroupReturn(ipt *iptables.IPTables, ipsetName string) error {
	if ipt == nil {
		return nil
	}
	chain := r.chainName()
	table := "mangle"

	if err := ipt.Delete(table, chain,
		"-m", "set", "--match-set", ipsetName, "dst",
		"-j", "RETURN",
	); err != nil {
		return fmt.Errorf("failed to delete RETURN rule for %s: %w", ipsetName, err)
	}
	if err := ipt.Commit(); err != nil {
		return fmt.Errorf("failed to commit RETURN rule delete for %s: %w", ipsetName, err)
	}
	return nil
}

// AddGroupReturn inserts RETURN rules in MT_SNI for both v4 and v6
// ipsets of a group.
func (r *SNIRules) AddGroupReturn(v4Name, v6Name string) error {
	var errs []error
	errs = append(errs, r.addGroupReturn(r.nh.IPTables4, v4Name))
	errs = append(errs, r.addGroupReturn(r.nh.IPTables6, v6Name))
	return errors.Join(errs...)
}

// DelGroupReturn removes the RETURN rules for a group from MT_SNI.
func (r *SNIRules) DelGroupReturn(v4Name, v6Name string) error {
	var errs []error
	errs = append(errs, r.delGroupReturn(r.nh.IPTables4, v4Name))
	errs = append(errs, r.delGroupReturn(r.nh.IPTables6, v6Name))
	return errors.Join(errs...)
}

func (r *SNIRules) deleteRules(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	var errs []error
	chain := r.chainName()
	table := "mangle"

	if err := ipt.Delete(table, "PREROUTING", "-j", chain); err != nil {
		errs = append(errs, fmt.Errorf("failed to unlink %s from %s/PREROUTING: %w", chain, table, err))
	}

	if err := ipt.RegisterChainDelete(table, chain); err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain %s: %w", chain, err))
	}

	if err := ipt.Commit(); err != nil {
		errs = append(errs, fmt.Errorf("failed to commit iptables rules: %w", err))
	}
	return errors.Join(errs...)
}

func (r *SNIRules) enable() error {
	if !r.enabled.CompareAndSwap(false, true) {
		return nil
	}

	if err := r.insertRules(r.nh.IPTables4); err != nil {
		r.disable()
		return err
	}
	if err := r.insertRules(r.nh.IPTables6); err != nil {
		r.disable()
		return err
	}
	return nil
}

func (r *SNIRules) disable() error {
	if !r.enabled.Load() {
		return nil
	}
	defer r.enabled.Store(false)

	var errs []error
	errs = append(errs, r.deleteRules(r.nh.IPTables4))
	errs = append(errs, r.deleteRules(r.nh.IPTables6))
	return errors.Join(errs...)
}

// Enable installs the MT_SNI chain. Safe to call repeatedly — the
// chainOverride mode means each Enable flushes and rewrites the chain
// rather than appending duplicates.
func (r *SNIRules) Enable() error {
	r.locker.Lock()
	defer r.locker.Unlock()
	return r.enable()
}

// Disable removes MT_SNI from PREROUTING and deletes the chain.
func (r *SNIRules) Disable() error {
	r.locker.Lock()
	defer r.locker.Unlock()
	return r.disable()
}

func (r *SNIRules) Enabled() bool {
	return r.enabled.Load()
}

// SNIRules returns a lazy view bound to the helper. Call Enable() to
// materialise the iptables rules. The NFQUEUE fallback matches all TCP
// flows; the sniffer's parser filters per payload.
func (nh *Helper) SNIRules(queueNum uint16) *SNIRules {
	return &SNIRules{
		nh:       nh,
		queueNum: queueNum,
	}
}
