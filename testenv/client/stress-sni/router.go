package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SnifferStats mirrors the backend's SNISnifferStatsRes JSON shape.
type SnifferStats struct {
	PacketsTotal      uint64    `json:"packets_total"`
	HitsTotal         uint64    `json:"hits_total"`
	MissesTotal       uint64    `json:"misses_total"`
	ParseFailures     uint64    `json:"parse_failures"`
	EmptyPayloadTotal uint64    `json:"empty_payload_total"`
	StitchedHits      uint64    `json:"stitched_hits"`
	PacketsPerSec     float64   `json:"packets_per_sec"`
	StartedAt         time.Time `json:"started_at"`
	Active            bool      `json:"active"`
}

// TimePoint is a single row in the soak-mode time series.
type TimePoint struct {
	ElapsedSec    int     `json:"elapsed_sec"`
	HitsTotal     uint64  `json:"hits_total"`
	PacketsPerSec float64 `json:"packets_per_sec"`
}

// Sampler polls the router's /api/v1/sniffer/stats endpoint on demand.
type Sampler struct {
	url    string
	client *http.Client

	startStats SnifferStats
	endStats   SnifferStats
	points     []TimePoint
	startTime  time.Time
}

func newSampler(routerURL string) *Sampler {
	return &Sampler{
		url:    routerURL + "/api/v1/sniffer/stats",
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// snapshotStart captures the baseline before the test begins.
func (s *Sampler) snapshotStart() error {
	return s.fetch(&s.startStats)
}

// snapshotEnd captures the final state after the test ends.
func (s *Sampler) snapshotEnd() (SnifferStats, error) {
	if err := s.fetch(&s.endStats); err != nil {
		return SnifferStats{}, err
	}
	return s.endStats, nil
}

// poll records a time-series data point. Call from a background goroutine.
func (s *Sampler) poll(elapsedSec int) {
	var stats SnifferStats
	if err := s.fetch(&stats); err != nil {
		return
	}
	s.points = append(s.points, TimePoint{
		ElapsedSec:    elapsedSec,
		HitsTotal:     stats.HitsTotal,
		PacketsPerSec: stats.PacketsPerSec,
	})
}

// timeSeries returns the collected points.
func (s *Sampler) timeSeries() []TimePoint { return s.points }

// endpointStats returns the final stats for the report.
func (s *Sampler) endpointStats() SnifferStats { return s.endStats }

func (s *Sampler) fetch(dst *SnifferStats) error {
	resp, err := s.client.Get(s.url)
	if err != nil {
		return fmt.Errorf("router API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("router API returned %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
