package sniffer

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
)

// diagnosticSink captures the first 16 bytes of every payload that
// reaches Parse() but fails to match. The capture is gated behind a
// process-global flag (set via the SNI_SNIFFER_DUMP environment
// variable) so production deployments incur zero overhead. The
// captured bytes are appended to /tmp/sni-payload-dump.log inside the
// daemon container; one line per packet, hex encoded so non-printable
// bytes survive the trip through `docker logs`. The flag and file
// descriptor are evaluated once at process start.
//
// This is intentionally coarse: when end-to-end validation completes
// we will either remove the hook entirely or gate it behind a config
// flag. The goal right now is to find out why Parse returns Hit=false
// for packets that the NFQUEUE iptables rule says should contain a
// TLS ClientHello.
var diagnosticEnabled atomic.Bool
var diagnosticFd atomic.Pointer[os.File]

func init() {
	val := os.Getenv("SNI_SNIFFER_DUMP")
	// Visible breadcrumb so we can confirm init() ran with the
	// expected env. The file lives inside the container at
	// /tmp/magitrickle-init.log; this is a one-shot sanity check,
	// remove once the sniffer dump is stable.
	_ = os.WriteFile("/tmp/magitrickle-init.log",
		[]byte(fmt.Sprintf("init: SNI_SNIFFER_DUMP=%q fd_set=%v\n", val, val == "1")), 0o644)
	if val == "1" {
		f, err := os.OpenFile("/tmp/sni-payload-dump.log",
			os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_TRUNC, 0o644)
		if err != nil {
			_ = os.WriteFile("/tmp/magitrickle-init.log",
				[]byte(fmt.Sprintf("init: open failed: %v\n", err)), 0o644)
			return
		}
		diagnosticFd.Store(f)
		diagnosticEnabled.Store(true)
	}
}

// lastParserFail is set by parseDispatch via setParserFail whenever a
// sub-parser bails out. Combined with the dumpPayloadForDebug side
// channel, this lets us see exactly which step rejected a real
// ClientHello (legacy_version check? session_id read? extensions
// walk? SNI list empty?). Reset before each Parse call.
var lastParserFail atomic.Pointer[string]

func setParserFail(stage string) { lastParserFail.Store(&stage) }

// dumpPayloadForDebug writes the first 64 bytes of payload (hex) to
// /tmp/sni-payload-dump.log when the env-gated diagnostic is on and
// the parser returned Hit=false. Each line is prefixed with the
// parser stage that produced the rejection (or "unknown" when the
// dispatch fell through the switch).
func dumpPayloadForDebug(payload []byte, hit bool) {
	if !diagnosticEnabled.Load() || hit {
		return
	}
	stage := "unknown"
	if p := lastParserFail.Load(); p != nil {
		stage = *p
	}
	diagnosticDump(payload, stage)
}

// diagnosticDump is the unconditional variant: writes a hex line with
// the supplied stage label, regardless of whether the parser hit or
// missed. Used by the stitching path to dump assembled multi-segment
// buffers that the parser already rejected once via dumpPayloadForDebug.
func diagnosticDump(payload []byte, stage string) {
	if !diagnosticEnabled.Load() {
		return
	}
	fd := diagnosticFd.Load()
	if fd == nil {
		return
	}
	const n = 256
	limit := len(payload)
	if limit > n {
		limit = n
	}
	hex := make([]byte, 0, 80+limit*3)
	hex = append(hex, '[')
	hex = append(hex, stage...)
	hex = append(hex, "] len="...)
	hex = strconv.AppendInt(hex, int64(len(payload)), 10)
	hex = append(hex, ' ')
	const hexDigits = "0123456789abcdef"
	for _, b := range payload[:limit] {
		hex = append(hex, hexDigits[b>>4], hexDigits[b&0x0f], ' ')
	}
	hex = append(hex, '\n')
	_, _ = fd.Write(hex)
}

// Reason describes why a parse call returned a particular result.
// It is used by the NFQUEUE loop to distinguish hits from misses
// from malformed-input failures when populating counters.
type Reason uint8

const (
	ReasonEmpty Reason = iota
	ReasonHit
	ReasonMissed
	ReasonParseError
)

// SniffResult is what the parsers hand back to the NFQUEUE loop. When
// Hit is false the rest of the fields are zero values and the sniffer
// silently ACCEPTs the packet. The domain string is borrowed (not
// copied) from the input slice; callers that queue it across
// goroutines (Phase 4) must clone it first.
type SniffResult struct {
	Hit      bool
	Domain   string
	Protocol Protocol
	Reason   Reason
}

// Parse dispatches a single TCP payload to the appropriate protocol
// parser. Each sub-parser is gated by the corresponding config flag so
// users can disable, for example, HTTP/2 if its HPACK cost is too high
// on a small router. A first byte that matches none of the known
// markers returns OK=false and the packet is accepted without further
// action.
//
// Detection rules, in order:
//   - 0x16 → TLS Handshake (most common on 443)
//   - "PRI * HTTP/2.0\r\n\r\n" prefix → HTTP/2 connection preface
//     (checked before HTTP/1.1 because both share the leading 'P')
//   - 'G', 'P', 'H', 'D', 'O', 'C' followed by an ASCII letter or space
//     → HTTP/1.1 method token (GET/POST/PUT/PATCH/HEAD/DELETE/OPTIONS/CONNECT)
func Parse(payload []byte, cfg Config) SniffResult {
	if len(payload) == 0 {
		return SniffResult{}
	}
	lastParserFail.Store(nil)
	res := parseDispatch(payload, cfg)
	dumpPayloadForDebug(payload, res.Hit)
	return res
}

func parseDispatch(payload []byte, cfg Config) SniffResult {
	switch payload[0] {
	case 0x16:
		if !cfg.EnableTLS {
			setParserFail("tls:disabled")
			return SniffResult{}
		}
		return sniffTLS(payload)
	}

	// HTTP/2 connection preface must win over the HTTP/1.1 'P' case
	// (POST/PUT/PATCH/PRI all start with the same byte). The full 24
	// byte preface is the cheapest discriminator.
	if cfg.EnableHTTP2 && bytes.HasPrefix(payload, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		return parseHTTP2Initial(payload)
	}

	switch payload[0] {
	case 'G', 'P', 'H', 'D', 'O', 'C':
		if !cfg.EnableHTTP {
			setParserFail("http1:disabled")
			return SniffResult{}
		}
		return parseHTTP1Request(payload)
	}

	setParserFail("dispatch:unknown_proto")
	return SniffResult{}
}