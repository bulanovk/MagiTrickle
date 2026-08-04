package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	mode := flag.String("mode", "burst", "test mode: burst or soak")
	workers := flag.Int("workers", 50, "concurrent TLS workers (burst mode)")
	rate := flag.Int("rate", 10, "connections per second (soak mode)")
	duration := flag.Duration("duration", 30*time.Second, "test duration")
	domainsFile := flag.String("domains", "/usr/local/share/stress-domains.txt", "path to domain list")
	routerURL := flag.String("router", "http://172.18.0.2:8080", "router API base URL")
	output := flag.String("output", "/tmp/stress-report.json", "JSON report path")
	flag.Parse()

	if *rate < 1 {
		log.Fatalf("-rate must be >= 1, got %d", *rate)
	}
	if *workers < 1 {
		log.Fatalf("-workers must be >= 1, got %d", *workers)
	}

	// Load domains.
	domains, err := loadDomains(*domainsFile)
	if err != nil {
		log.Fatalf("load domains: %v", err)
	}
	log.Printf("loaded %d domains", len(domains))

	// Check ulimit.
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err == nil && rlim.Cur < 1024 {
		log.Printf("WARNING: ulimit -n is %d (recommend ≥ 1024)", rlim.Cur)
	}

	// Snapshot router baseline.
	sampler := newSampler(*routerURL)
	if err := sampler.snapshotStart(); err != nil {
		log.Printf("WARNING: router API unavailable: %v (sniffer may be inactive)", err)
	}

	// Setup.
	results := make(chan WorkerResult, 1024)
	stop := make(chan struct{})
	var failed atomic.Int64
	latency := newLatencyCollector()

	// Collector goroutine — drains results channel into latency collector.
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for r := range results {
			latency.add(r.Latency)
		}
	}()

	// Background router polling (every second).
	var pollWG sync.WaitGroup
	pollWG.Add(1)
	go func() {
		defer pollWG.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		elapsed := 0
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				elapsed++
				sampler.poll(elapsed)
			}
		}
	}()

	// Signal handler — graceful shutdown on Ctrl-C.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Launch workers or rate-limited loop.
	startTime := time.Now()
	var workersWG sync.WaitGroup
	var launcherWG sync.WaitGroup
	launchWorker := func() {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			runWorker(domains, 5*time.Second, 5*time.Second, results, &failed, stop)
		}()
	}

	switch *mode {
	case "burst":
		for i := 0; i < *workers; i++ {
			launchWorker()
		}
	case "soak":
		launcherWG.Add(1)
		go func() {
			defer launcherWG.Done()
			ticker := time.NewTicker(time.Second / time.Duration(*rate))
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					launchWorker()
				}
			}
		}()
	default:
		log.Fatalf("unknown mode: %s (use burst or soak)", *mode)
	}

	// Wait for duration or stop signal.
	timer := time.NewTimer(*duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-sigCh:
		log.Println("interrupted, stopping...")
	}
	close(stop)

	// Stop the launcher before waiting so it cannot add another worker.
	launcherWG.Wait()
	closeResultsAfterWorkers(&workersWG, results)
	collectorWG.Wait()
	pollWG.Wait()

	elapsed := time.Since(startTime)

	// Final router snapshot.
	finalStats, err := sampler.snapshotEnd()
	if err != nil {
		log.Printf("WARNING: final router snapshot failed: %v", err)
	}

	// Build report.
	handshakesOK := latency.count()
	report := Report{
		Mode:     *mode,
		Duration: elapsed,
		Workers:  *workers,
		Rate:     *rate,
		Client: ClientReport{
			HandshakesTotal:  handshakesOK,
			HandshakesFailed: int(failed.Load()),
			HandshakesPerSec: float64(handshakesOK) / elapsed.Seconds(),
			LatencyP50:       latency.percentile(0.50),
			LatencyP95:       latency.percentile(0.95),
			LatencyP99:       latency.percentile(0.99),
		},
		Router: RouterReport{
			Active:            finalStats.Active,
			PacketsTotal:      finalStats.PacketsTotal,
			HitsTotal:         finalStats.HitsTotal,
			MissesTotal:       finalStats.MissesTotal,
			ParseFailures:     finalStats.ParseFailures,
			EmptyPayloadTotal: finalStats.EmptyPayloadTotal,
			StitchedHits:      finalStats.StitchedHits,
			PacketsPerSec:     finalStats.PacketsPerSec,
		},
		TimeSeries: sampler.timeSeries(),
	}

	// Derive hit rate.
	if handshakesOK > 0 && finalStats.HitsTotal > 0 {
		hitRate := float64(finalStats.HitsTotal) / float64(handshakesOK) * 100
		report.Router.HitRatePct = hitRate
	}

	// Write JSON.
	j, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(*output, j, 0o644); err != nil {
		log.Printf("WARNING: write report: %v", err)
	}

	// Print text summary.
	fmt.Println(report.Text())
	log.Printf("report written to %s", *output)
}

// Report is the complete stress test result, serialised to JSON.
type Report struct {
	Mode       string        `json:"mode"`
	Duration   time.Duration `json:"duration_ns"`
	Workers    int           `json:"workers"`
	Rate       int           `json:"rate"`
	Client     ClientReport  `json:"client"`
	Router     RouterReport  `json:"router"`
	TimeSeries []TimePoint   `json:"time_series,omitempty"`
}

// ClientReport holds client-side metrics.
type ClientReport struct {
	HandshakesTotal  int           `json:"handshakes_total"`
	HandshakesFailed int           `json:"handshakes_failed"`
	HandshakesPerSec float64       `json:"handshakes_per_sec"`
	LatencyP50       time.Duration `json:"latency_p50_ns"`
	LatencyP95       time.Duration `json:"latency_p95_ns"`
	LatencyP99       time.Duration `json:"latency_p99_ns"`
}

// RouterReport holds router-side sniffer metrics.
type RouterReport struct {
	Active            bool    `json:"sniffer_active"`
	PacketsTotal      uint64  `json:"packets_total"`
	HitsTotal         uint64  `json:"hits_total"`
	MissesTotal       uint64  `json:"misses_total"`
	ParseFailures     uint64  `json:"parse_failures"`
	EmptyPayloadTotal uint64  `json:"empty_payload_total"`
	StitchedHits      uint64  `json:"stitched_hits"`
	PacketsPerSec     float64 `json:"packets_per_sec"`
	HitRatePct        float64 `json:"hit_rate_pct,omitempty"`
}

// Text returns a human-readable summary.
func (r *Report) Text() string {
	s := fmt.Sprintf(`=== STRESS-SNI REPORT ===
Mode: %s | Duration: %.0fs | Workers: %d | Rate: %d/s

CLIENT:
  Handshakes:    %d total | %d errors
  Rate:          %.1f handshakes/s
  Latency:       p50=%s p95=%s p99=%s

ROUTER (sniffer):
  Active:        %v`,
		r.Mode, r.Duration.Seconds(), r.Workers, r.Rate,
		r.Client.HandshakesTotal, r.Client.HandshakesFailed,
		r.Client.HandshakesPerSec,
		r.Client.LatencyP50, r.Client.LatencyP95, r.Client.LatencyP99,
		r.Router.Active,
	)
	if r.Router.Active {
		s += fmt.Sprintf(`
  Hits:          %d (%.1f%%)
  Misses:        %d | Stitched: %d
  ParseFailures: %d | Empty: %d
  Throughput:    %.1f packets/s (final)`,
			r.Router.HitsTotal, r.Router.HitRatePct,
			r.Router.MissesTotal, r.Router.StitchedHits,
			r.Router.ParseFailures, r.Router.EmptyPayloadTotal,
			r.Router.PacketsPerSec,
		)
	}
	if len(r.TimeSeries) > 0 {
		s += fmt.Sprintf("\n  Time points:   %d samples over %.0fs", len(r.TimeSeries), r.Duration.Seconds())
	}
	return s
}

// loadDomains reads a file, one domain per line, skipping empty lines.
func loadDomains(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			domains = append(domains, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("domain list is empty")
	}
	return domains, nil
}

func closeResultsAfterWorkers(workers *sync.WaitGroup, results chan WorkerResult) {
	workers.Wait()
	close(results)
}
