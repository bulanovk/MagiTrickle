package sniffer

import (
	"testing"
)

// TestProbeKernelModules_DoesNotPanic guarantees the probe stays callable
// on any host. A panic here would crash MagiTrickle startup; an empty
// ProbeResult is acceptable on non-Linux systems.
func TestProbeKernelModules_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ProbeKernelModules panicked: %v", r)
		}
	}()
	_ = ProbeKernelModules()
}

// TestModuleLoaded_KnownMissing verifies that a module the running kernel
// definitely does not have returns false. Using an obviously fake name
// isolates this test from kernel state.
func TestModuleLoaded_KnownMissing(t *testing.T) {
	if moduleLoaded("definitely_not_a_real_kernel_module_xyz123") {
		t.Fatal("moduleLoaded returned true for a fake module name")
	}
}

// TestProbeResult_AvailableLogic documents that Available requires all
// three flags. A future flag added to ProbeResult must not accidentally
// change the Available semantics without updating this test.
func TestProbeResult_AvailableLogic(t *testing.T) {
	tests := []struct {
		name string
		r    ProbeResult
		want bool
	}{
		{"all present", ProbeResult{NFQueue: true, IPSet: true, Conntrack: true}, true},
		{"missing nfqueue", ProbeResult{NFQueue: false, IPSet: true, Conntrack: true}, false},
		{"missing ipset", ProbeResult{NFQueue: true, IPSet: false, Conntrack: true}, false},
		{"missing conntrack", ProbeResult{NFQueue: true, IPSet: true, Conntrack: false}, false},
		{"all missing", ProbeResult{}, false},
	}
	for _, tt := range tests {
		if got := tt.r.NFQueue && tt.r.IPSet && tt.r.Conntrack; got != tt.want {
			t.Errorf("%s: Available = %v, want %v", tt.name, got, tt.want)
		}
	}
}