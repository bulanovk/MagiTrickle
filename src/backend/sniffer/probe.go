package sniffer

import "os"

// ProbeResult describes which kernel modules are present on the host.
type ProbeResult struct {
	// NFQueue reports xt_NFQUEUE.ko presence. Without it, NFQUEUE iptables
	// matches fail and traffic cannot be handed to userspace.
	NFQueue bool

	// IPSet reports ip_set + xt_set.ko presence. Required for the
	// per-rule hash:net sets used by group RETURN rules.
	IPSet bool

	// Conntrack reports nf_conntrack presence. Required for the
	// conntrack-driven iptables matches used elsewhere in MagiTrickle
	// (--ctdir REPLY) and as a sanity signal that the box has full
	// netfilter support, not for any sniffer-internal matching.
	Conntrack bool

	// Available is true iff all three of the above are loaded. It is the
	// single boolean the caller should test before enabling the sniffer.
	Available bool
}

// kernelModuleDirs enumerates the sysfs entries that prove each module is
// loaded. The presence of /sys/module/<name> is the standard Linux signal
// that the module has been initialised in the running kernel.
var kernelModuleDirs = []struct {
	name string
	dest *bool
}{
	{"xt_NFQUEUE", new(bool)},
	{"ip_set", new(bool)},
	{"nf_conntrack", new(bool)},
}

// ProbeKernelModules checks /sys/module for the entries NFQUEUE-based
// sniffing requires. It is safe to call on any OS; on non-Linux the
// /sys/module directory does not exist and all flags stay false.
//
// On Keenetic routers the modules live in the NDMS firmware layer; users
// must install the "Kernel modules for Netfilter" component from the WebUI
// before this probe returns Available=true.
func ProbeKernelModules() ProbeResult {
	var r ProbeResult
	for _, m := range kernelModuleDirs {
		if moduleLoaded(m.name) {
			*m.dest = true
		}
	}
	r.NFQueue = *kernelModuleDirs[0].dest
	r.IPSet = *kernelModuleDirs[1].dest
	r.Conntrack = *kernelModuleDirs[2].dest
	r.Available = r.NFQueue && r.IPSet && r.Conntrack
	return r
}

// moduleLoaded returns true when /sys/module/<name> exists. We only stat
// the directory itself; module parameters under it are not consulted.
func moduleLoaded(name string) bool {
	info, err := os.Stat("/sys/module/" + name)
	if err != nil {
		return false
	}
	return info.IsDir()
}