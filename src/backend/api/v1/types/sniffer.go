package types

import "time"

// SNISnifferConfigRes mirrors models.AppConfigSNISniffer for the API.
// Field names match the YAML keys so the frontend can render the
// response verbatim into a form.
type SNISnifferConfigRes struct {
	Enabled        bool          `json:"enabled"`
	QueueNum       uint16        `json:"queue_num"`
	MaxQueueLen    uint32        `json:"max_queue_len"`
	MaxPacketLen   uint32        `json:"max_packet_len"`
	EnableTLS      bool          `json:"enable_tls"`
	EnableHTTP     bool          `json:"enable_http"`
	EnableHTTP2    bool          `json:"enable_http2"`
	AllowedPorts   []uint16      `json:"allowed_ports"`
	AdditionalTTL  time.Duration `json:"additional_ttl_ns"`
	LogDNSMismatch bool          `json:"log_dns_mismatch"`
}

// SNISnifferStatsRes is the public view of sniffer counters. Time
// fields are emitted as RFC3339 strings so the frontend can format
// them without parsing nanoseconds.
type SNISnifferStatsRes struct {
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

// SNISnifferRecentRes returns a slice of live SNI observations for
// the /sniffer/recent endpoint.
type SNISnifferRecentRes struct {
	Observations []SNISnifferObservationRes `json:"observations"`
}

// SNISnifferObservationRes is the JSON-serialisable view of a single
// observation. ExpiresIn is the remaining seconds before the
// observation is purged from the records cache.
type SNISnifferObservationRes struct {
	IP        string        `json:"ip"`
	Domain    string        `json:"domain"`
	Observed  time.Time     `json:"observed"`
	ExpiresIn time.Duration `json:"expires_in_ns"`
}
