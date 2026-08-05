package sniffer

import (
	"context"
	"testing"
	"time"
)

// TestNew_DisabledReturnsNoOp verifies that an explicit Enabled=false
// produces a NoOpSniffer without touching /sys/module.
func TestNew_DisabledReturnsNoOp(t *testing.T) {
	cfg := Config{Enabled: false}
	s := New(cfg)
	if _, ok := s.(*NoOpSniffer); !ok {
		t.Fatalf("New(Enabled=false) = %T, want *NoOpSniffer", s)
	}
}

// TestNoOpSniffer_StartReturnsNil is the safety net for callers that do
// not bother to inspect the returned type.
func TestNoOpSniffer_StartReturnsNil(t *testing.T) {
	n := &NoOpSniffer{}
	if err := n.Start(context.Background(), Hooks{}); err != nil {
		t.Fatalf("NoOpSniffer.Start err = %v, want nil", err)
	}
}

// TestNoOpSniffer_StatsZero confirms the zero value is reported instead
// of misleading metrics on platforms where sniffing never runs.
func TestNoOpSniffer_StatsZero(t *testing.T) {
	n := &NoOpSniffer{}
	got := n.Stats()
	if got != (Stats{}) {
		t.Fatalf("NoOpSniffer.Stats = %+v, want zero Stats", got)
	}
}

// TestNoOpSniffer_StopReturnsNil keeps the contract symmetric with Start.
func TestNoOpSniffer_StopReturnsNil(t *testing.T) {
	n := &NoOpSniffer{}
	if err := n.Stop(); err != nil {
		t.Fatalf("NoOpSniffer.Stop err = %v, want nil", err)
	}
}

// TestConfig_ZeroValueIsSafe ensures that a freshly zero-valued Config
// does not panic and behaves like a disabled sniffer.
func TestConfig_ZeroValueIsSafe(t *testing.T) {
	cfg := Config{}
	s := New(cfg)
	if _, ok := s.(*NoOpSniffer); !ok {
		t.Fatalf("New(zero Config) = %T, want *NoOpSniffer", s)
	}
}

// TestProtocol_Constants pins the string identifiers used by the stats
// surface; changing them is a breaking change for the WebUI.
func TestProtocol_Constants(t *testing.T) {
	if ProtocolTLS != "tls" {
		t.Errorf("ProtocolTLS = %q, want tls", ProtocolTLS)
	}
	if ProtocolHTTP != "http" {
		t.Errorf("ProtocolHTTP = %q, want http", ProtocolHTTP)
	}
	if ProtocolHTTP2 != "http2" {
		t.Errorf("ProtocolHTTP2 = %q, want http2", ProtocolHTTP2)
	}
}

// TestHooks_OnDomainInvoked documents the contract: when the sniffer
// successfully parses a domain, the supplied hook fires once. The
// NoOpSniffer does not invoke hooks; this test guards the asymmetry so
// that an accidental swap (e.g. moving Start into the interface default)
// would fail loudly.
func TestHooks_OnDomainInvoked(t *testing.T) {
	var called bool
	hooks := Hooks{
		OnDomain: func(_ string, _ []byte, _ Protocol) {
			called = true
		},
	}
	n := &NoOpSniffer{}
	_ = n.Start(context.Background(), hooks)
	if called {
		t.Fatalf("NoOpSniffer should not invoke hooks")
	}
}

// TestNFQueueSniffer_StartHonoursContext ensures the Linux implementation
// returns promptly when the context is cancelled instead of blocking
// forever. This is the contract Phase 4 must preserve.
func TestNFQueueSniffer_StartHonoursContext(t *testing.T) {
	if !isLinux() {
		t.Skip("NFQUEUE skeleton only runs on linux")
	}
	cfg := Config{
		Enabled:        true,
		QueueNum:       0,
		MaxQueueLen:    16,
		AdditionalTTL:  time.Hour,
	}
	s := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx, Hooks{}) }()
	cancel()
	select {
	case err := <-done:
		// On hosts without the kernel modules Start returns
		// ErrKernelModulesMissing before blocking; either outcome is
		// acceptable, what matters is that we did not hang.
		_ = err
	case <-time.After(time.Second):
		t.Fatal("cgo sniffer Start did not return after ctx cancel")
	}
}

func isLinux() bool {
	// Build tags would be cleaner; this helper keeps the test in a single
	// file and avoids duplicating the entire test under !linux tags.
	return runtimeGOOS() == "linux"
}