// Package sniffer implements first-packet domain attribution for MagiTrickle.
// It complements the DNS-MITM path by parsing TLS ClientHello and HTTP Host
// / :authority headers from TCP flows whose destination IP is not yet in any
// active ipset. This catches DoH/DoT/DoQ traffic, ECH-protected flows, and
// IP-literal connections that bypass DNS resolution.
//
// Activation requires the Linux kernel modules xt_NFQUEUE, ip_set, and
// nf_conntrack. On platforms that lack them, New returns a NoOpSniffer so the
// rest of MagiTrickle continues to function unchanged.
package sniffer

import (
	"context"
	"time"
)

// Protocol identifies the application protocol whose first packet was parsed.
type Protocol string

const (
	ProtocolTLS   Protocol = "tls"
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTP2 Protocol = "http2"
)

// Config holds tunables for the SNI sniffer.
type Config struct {
	// Enabled is the master switch. When false, New returns a no-op sniffer.
	Enabled bool

	// QueueNum is the NFQUEUE queue number to bind to. Default 0.
	QueueNum uint16

	// MaxQueueLen is the kernel NFQUEUE buffer length. Default 1024.
	MaxQueueLen uint32

	// MaxPacketLen bounds the size of packet payload copied to
	// userspace. Default 0xFFFF — well over a TLS ClientHello. Smaller
	// values save RAM on a busy router but will truncate large HTTP/2
	// headers.
	MaxPacketLen uint32

	// EnableTLS controls parsing of TLS ClientHello (port 443).
	EnableTLS bool

	// EnableHTTP controls parsing of HTTP/1.1 Host headers (port 80).
	EnableHTTP bool

	// EnableHTTP2 controls parsing of HTTP/2 :authority pseudo-headers.
	EnableHTTP2 bool

	// AdditionalTTL extends ipset entries beyond DNS TTL. Default 1h.
	AdditionalTTL time.Duration
}

// Stats is a snapshot of sniffer metrics. Returned by Stats().
type Stats struct {
	PacketsTotal  uint64
	HitsTotal     uint64
	MissesTotal   uint64
	ParseFailures uint64
	// EmptyPayloadTotal counts packets whose TCP segment carried no
	// application-layer data — these are typically ACKs and
	// retransmissions. They used to be folded into MissesTotal, which
	// made it impossible to tell apart "parser did not recognise the
	// payload" (a real bug) from "no payload to parse" (expected). Kept
	// as a separate counter until the sniffer is end-to-end validated;
	// the field can be removed (and EmptyPayloadTotal can be re-merged
	// into MissesTotal) once we see hits on real ClientHello flows.
	EmptyPayloadTotal uint64
	// StitchedHits counts hits that required reassembling a ClientHello
	// across two or more TCP segments. Non-zero means TLS ClientHellos
	// in the test set are large enough to exceed MTU/MSS — confirms we
	// are testing real-world traffic and not empty-payload ACKs.
	StitchedHits  uint64
	PacketsPerSec float64
	StartedAt     time.Time
	Active        bool
}

// Hooks are callbacks invoked when the sniffer extracts a domain from a flow.
// Implementations typically forward the domain through the existing rule
// matcher and add the IP to the matching group's ipset.
type Hooks struct {
	// OnDomain is invoked when a domain is extracted. domain is the SNI,
	// Host header, or :authority pseudo-header; dstIP is the packet's
	// destination address; protocol is the parser that produced it.
	OnDomain func(domain string, dstIP []byte, protocol Protocol)
}

// Sniffer intercepts the first packet of new TCP flows and extracts the
// destination domain for downstream rule matching. The interface keeps the
// no-op implementation available for unit tests and platforms without NFQUEUE.
type Sniffer interface {
	// Start runs the sniffer until ctx is cancelled. The provided hooks
	// are invoked once per successfully parsed domain. The OnDomain hook
	// MUST be safe for concurrent calls; the sniffer may feed results
	// from multiple goroutines.
	Start(ctx context.Context, hooks Hooks) error

	// Stats returns the current counters.
	Stats() Stats

	// Stop releases resources. Idempotent.
	Stop() error
}

// New returns a Sniffer matching the runtime platform. On Linux it opens an
// NFQUEUE socket (pure-Go via florianl/go-nfqueue); elsewhere (or when
// Enabled is false) it returns a NoOpSniffer. The caller should still
// call ProbeKernelModules before Start to verify the kernel has the
// required modules.
func New(cfg Config) Sniffer {
	if !cfg.Enabled {
		return &NoOpSniffer{}
	}
	return newLinuxSniffer(cfg)
}

// NoOpSniffer is the safe fallback. All operations succeed without doing
// any work. Used when the feature is disabled, the kernel lacks the
// required modules, or the binary runs on a non-Linux OS.
type NoOpSniffer struct{}

func (n *NoOpSniffer) Start(_ context.Context, _ Hooks) error { return nil }
func (n *NoOpSniffer) Stats() Stats                           { return Stats{} }
func (n *NoOpSniffer) Stop() error                            { return nil }
