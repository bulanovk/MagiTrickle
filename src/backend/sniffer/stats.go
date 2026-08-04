package sniffer

import (
	"sync"
	"sync/atomic"
	"time"
)

// counters holds the sniffer's metric counters. The struct is updated
// from the NFQUEUE callback goroutine and read from the Stats() method,
// so every counter field uses sync/atomic for lock-free access.
//
// PacketsPerSec is the rate from the most recently completed wall-clock
// second. It is updated only when the second rolls over (i.e. before the
// first full second of activity, PacketsPerSec is zero — that is by
// design, not a bug). The watchdog (future phase) reads PacketsPerSec
// and disables the sniffer if it exceeds the configured threshold for
// sustained periods.
type counters struct {
	packets   atomic.Uint64
	hits      atomic.Uint64
	misses    atomic.Uint64
	failures  atomic.Uint64
	empty     atomic.Uint64
	// stitched counts ClientHello hits that required flow-aware
	// reassembly across multiple TCP segments (e.g. when MSS ≈ 1440
	// splits a 1537-byte CH into two segments). Without this counter
	// the operator cannot tell "parser works on whole records" from
	// "operator's CH never gets large enough to fragment".
	stitched  atomic.Uint64
	startedAt time.Time

	ppsMu        sync.Mutex
	ppsCurrent   int64   // unix-second of the bucket currently being filled
	ppsBucket    uint64  // packets received in ppsCurrent
	ppsLastFull  uint64  // packets received in the most recently completed second
}

// recordPacket increments the total packet counter and folds the
// hit/miss/failure triple in a single call so all three stay
// consistent. Called from the NFQUEUE callback.
func (c *counters) recordPacket(hit, miss, failure bool) {
	c.packets.Add(1)
	switch {
	case hit:
		c.hits.Add(1)
	case miss:
		c.misses.Add(1)
	case failure:
		c.failures.Add(1)
	}

	now := time.Now().Unix()
	c.ppsMu.Lock()
	if c.ppsCurrent != now {
		// Second rolled over — commit the previous bucket and start
		// the new one. We do not retain a longer history; the watchdog
		// only needs the most recent completed second.
		c.ppsLastFull = c.ppsBucket
		c.ppsBucket = 0
		c.ppsCurrent = now
	}
	c.ppsBucket++
	c.ppsMu.Unlock()
}

// snapshot reads the counters into a Stats value. PacketsPerSec
// reflects the last completed second; while still inside the first
// second of activity it is 0.
func (c *counters) recordEmpty() { c.empty.Add(1) }

// recordStitched increments the stitched-hits counter without
// touching hit/miss/fail. Called when a ClientHello only parses
// successfully after we have buffered at least one continuation
// TCP segment for the same 4-tuple. We still call recordHit() once
// the stitched parse succeeds so the global hit counter includes it;
// recordStitched is purely a "diagnostic of fragmentation" tag.
func (c *counters) recordStitched() { c.stitched.Add(1) }

func (c *counters) snapshot() Stats {
	c.ppsMu.Lock()
	pps := c.ppsLastFull
	c.ppsMu.Unlock()
	return Stats{
		PacketsTotal:     c.packets.Load(),
		HitsTotal:        c.hits.Load(),
		MissesTotal:      c.misses.Load(),
		ParseFailures:    c.failures.Load(),
		EmptyPayloadTotal: c.empty.Load(),
		StitchedHits:     c.stitched.Load(),
		PacketsPerSec:    float64(pps),
		StartedAt:        c.startedAt,
		Active:           true,
	}
}