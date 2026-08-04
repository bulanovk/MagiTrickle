package main

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// WorkerResult describes a single TLS handshake attempt.
type WorkerResult struct {
	OK      bool
	Latency time.Duration // valid only when OK
}

// runWorker opens TLS connections to random domains until stop is closed.
// Each iteration: pick random domain, dial TCP, TLS handshake with SNI,
// close, send result. DNS failures and connection timeouts are counted
// via the failed atomic.
func runWorker(
	domains []string,
	dialTimeout time.Duration,
	tlsTimeout time.Duration,
	results chan<- WorkerResult,
	failed *atomic.Int64,
	stop <-chan struct{},
) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsCfg}

	for {
		select {
		case <-stop:
			return
		default:
		}

		domain := domains[rand.Intn(len(domains))]
		addr := net.JoinHostPort(domain, "443")

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), tlsTimeout)
		conn, err := tlsDialer.DialContext(ctx, "tcp", addr)
		cancel()
		if err != nil {
			failed.Add(1)
			continue
		}
		elapsed := time.Since(start)
		conn.Close()

		select {
		case results <- WorkerResult{OK: true, Latency: elapsed}:
		case <-stop:
			return
		}
	}
}

// latencyCollector gathers handshake durations and computes percentiles.
// Safe for concurrent use via internal mutex.
type latencyCollector struct {
	mu       sync.Mutex
	samples  []time.Duration
	sorted   bool
}

func newLatencyCollector() *latencyCollector {
	return &latencyCollector{}
}

func (lc *latencyCollector) add(d time.Duration) {
	lc.mu.Lock()
	lc.samples = append(lc.samples, d)
	lc.sorted = false
	lc.mu.Unlock()
}

// percentile returns the p-th percentile (0..1). Sorts on first call.
func (lc *latencyCollector) percentile(p float64) time.Duration {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if len(lc.samples) == 0 {
		return 0
	}
	if !lc.sorted {
		sortDurations(lc.samples)
		lc.sorted = true
	}
	idx := int(float64(len(lc.samples)) * p)
	if idx >= len(lc.samples) {
		idx = len(lc.samples) - 1
	}
	return lc.samples[idx]
}

func (lc *latencyCollector) count() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return len(lc.samples)
}

// sortDurations is a simple insertion sort — fast enough for <100k samples.
func sortDurations(a []time.Duration) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
