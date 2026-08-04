package sniffer

import (
	"encoding/binary"
	"testing"
)

// buildClientHello constructs a minimal TLS ClientHello record. The
// resulting byte slice starts with a TLSPlaintext record header so
// the parser exercises the same path as a real packet capture.
func buildClientHello(tb testing.TB, domain string, opts ...clientHelloOpt) []byte {
	tb.Helper()
	cfg := clientHelloConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.legacyVersion == 0 {
		cfg.legacyVersion = 0x0303 // TLS 1.2 / 1.3
	}

	// extensions block
	var extBuf []byte
	if domain != "" {
		// server_name extension
		snName := []byte(domain)
		snEntry := append([]byte{0x00}, uint16Bytes(uint16(len(snName)))...)
		snEntry = append(snEntry, snName...)
		snList := uint16Bytes(uint16(len(snEntry)))
		snList = append(snList, snEntry...)
		snExt := append([]byte{}, uint16Bytes(tlsExtServerName)...)
		snExt = append(snExt, uint16Bytes(uint16(len(snList)))...)
		snExt = append(snExt, snList...)
		extBuf = append(extBuf, snExt...)
	}
	if cfg.ech {
		// ECH outer extension with a dummy body. Length is non-zero so
		// the parser actually advances past it.
		echBody := []byte{0x00, 0x00, 0x20, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00}
		echExt := uint16Bytes(0xfe0d)
		echExt = append(echExt, uint16Bytes(uint16(len(echBody)))...)
		echExt = append(echExt, echBody...)
		extBuf = append(extBuf, echExt...)
	}
	extBlock := uint16Bytes(uint16(len(extBuf)))
	extBlock = append(extBlock, extBuf...)

	// session_id (empty is the most common modern value)
	sessionID := []byte{0x00}

	// cipher_suites: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f) and TLS_AES_128_GCM_SHA256 (0x1301)
	cipherSuites := uint16Bytes(4)
	cipherSuites = append(cipherSuites, 0x00, 0x2f, 0x13, 0x01)

	// compression: null only
	compression := []byte{0x01, 0x00}

	// Handshake body
	var hsBody []byte
	hsBody = append(hsBody, uint16Bytes(cfg.legacyVersion)...)
	hsBody = append(hsBody, make([]byte, 32)...) // random
	hsBody = append(hsBody, sessionID...)
	hsBody = append(hsBody, cipherSuites...)
	hsBody = append(hsBody, compression...)
	if cfg.noExtensions {
		hsBody = append(hsBody, 0x00, 0x00) // empty extensions
	} else {
		hsBody = append(hsBody, extBlock...)
	}

	// Handshake header
	hsHeader := []byte{0x01} // ClientHello
	hsHeader = append(hsHeader, uint24Bytes(uint32(len(hsBody)))...)
	hsHeader = append(hsHeader, hsBody...)

	// TLSPlaintext record
	record := []byte{0x16, 0x03, 0x01}
	record = append(record, uint16Bytes(uint16(len(hsHeader)))...)
	record = append(record, hsHeader...)
	return record
}

// tlsExtServerName is the server_name extension type code per
// RFC 6066 §3. Copied here because the prod parser is inlined into
// parser_tls.go and intentionally avoids exporting such constants —
// the test wants the value as a literal so a future refactor of the
// test's parser would still have access to the RFC number.
const tlsExtServerName = 0x0000

type clientHelloConfig struct {
	legacyVersion uint16
	noExtensions  bool
	ech           bool
}

type clientHelloOpt func(*clientHelloConfig)

func withLegacyVersion(v uint16) clientHelloOpt {
	return func(c *clientHelloConfig) { c.legacyVersion = v }
}

func withNoExtensions() clientHelloOpt {
	return func(c *clientHelloConfig) { c.noExtensions = true }
}

func withECH() clientHelloOpt {
	return func(c *clientHelloConfig) { c.ech = true }
}

func uint16Bytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func uint24Bytes(v uint32) []byte {
	return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

// ------------------- Tests -------------------

func TestParseTLS_BasicSNI(t *testing.T) {
	payload := buildClientHello(t, "example.com")
	cfg := Config{EnableTLS: true}
	got := Parse(payload, cfg)
	if !got.Hit {
		t.Fatal("expected OK=true")
	}
	if got.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", got.Domain)
	}
	if got.Protocol != ProtocolTLS {
		t.Errorf("Protocol = %q, want tls", got.Protocol)
	}
}

func TestParseTLS_TLS13SNI(t *testing.T) {
	// TLS 1.3 ClientHellos use legacy_version=0x0303 too — the parser
	// cannot tell them apart and that is fine; the supported_versions
	// extension is what actually pins the version. We just want to
	// confirm the SNI path still works.
	payload := buildClientHello(t, "www.google.com")
	cfg := Config{EnableTLS: true}
	got := Parse(payload, cfg)
	if !got.Hit || got.Domain != "www.google.com" {
		t.Fatalf("got %+v, want domain=www.google.com", got)
	}
}

func TestParseTLS_DisabledReturnsFalse(t *testing.T) {
	payload := buildClientHello(t, "example.com")
	cfg := Config{EnableTLS: false}
	got := Parse(payload, cfg)
	if got.Hit {
		t.Fatalf("expected OK=false when EnableTLS=false, got %+v", got)
	}
}

func TestParseTLS_NoExtensions(t *testing.T) {
	payload := buildClientHello(t, "", withNoExtensions())
	cfg := Config{EnableTLS: true}
	got := Parse(payload, cfg)
	if got.Hit {
		t.Fatalf("expected OK=false for no-extensions ClientHello, got %+v", got)
	}
}

func TestParseTLS_BadLegacyVersion(t *testing.T) {
	// Vendored xray parser only validates the TLS record header
	// version (b[1] == 0x03). It deliberately does NOT inspect the
	// handshake body's legacy_version field, because the only real
	// signal of "this is TLS" at the record layer is record_version
	// itself. A peer that sets handshake.legacy_version to anything
	// non-TLS while keeping record.version_major == 3 still produces
	// a valid TLS ClientHello from xray's perspective. This test
	// documents that choice: buildClientHello with legacyVersion=0x0200
	// still hits because record header is 16 03 01.
	payload := buildClientHello(t, "example.com", withLegacyVersion(0x0200))
	cfg := Config{EnableTLS: true}
	got := Parse(payload, cfg)
	if !got.Hit || got.Domain != "example.com" {
		t.Fatalf("expected hit for record-header-only TLS validation, got %+v", got)
	}
}

func TestParseTLS_TruncatedRecord(t *testing.T) {
	payload := buildClientHello(t, "example.com")
	cfg := Config{EnableTLS: true}
	for cut := 1; cut < 10 && cut < len(payload); cut++ {
		if got := Parse(payload[:cut], cfg); got.Hit {
			t.Fatalf("truncation to %d bytes produced OK result: %+v", cut, got)
		}
	}
}

func TestParseTLS_NotHandshake(t *testing.T) {
	payload := []byte{0x17, 0x03, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	cfg := Config{EnableTLS: true}
	got := Parse(payload, cfg)
	if got.Hit {
		t.Fatalf("expected OK=false for 0x17 record, got %+v", got)
	}
}

func TestParseTLS_ECHDoesNotPanic(t *testing.T) {
	// ECH extension present alongside SNI: parser should ignore ECH
	// and still recover the SNI.
	payload := buildClientHello(t, "cdn.example.com", withECH())
	cfg := Config{EnableTLS: true}
	got := Parse(payload, cfg)
	if !got.Hit || got.Domain != "cdn.example.com" {
		t.Fatalf("ECH+ SNI got %+v, want domain=cdn.example.com", got)
	}
}

func TestParseTLS_ECHOnlyNoSNI(t *testing.T) {
	// ECH only, no server_name — we must return OK=false rather than
	// fake a match.
	payload := buildClientHello(t, "", withECH())
	cfg := Config{EnableTLS: true}
	got := Parse(payload, cfg)
	if got.Hit {
		t.Fatalf("ECH-only got %+v, want OK=false", got)
	}
}

func TestParseTLS_BrokenSessionID(t *testing.T) {
	// Garbage in the middle of the ClientHello — parser must fail
	// gracefully without panicking.
	payload := buildClientHello(t, "example.com")
	// Corrupt the session_id length byte to 0xFF (way past end of record).
	payload[5+1+2+3+2+32] = 0xff
	cfg := Config{EnableTLS: true}
	got := Parse(payload, cfg)
	if got.Hit {
		t.Fatalf("corrupt payload produced OK result: %+v", got)
	}
}

func TestParse_EmptyPayload(t *testing.T) {
	got := Parse(nil, Config{EnableTLS: true, EnableHTTP: true, EnableHTTP2: true})
	if got.Hit {
		t.Fatalf("nil payload produced %+v", got)
	}
}

func TestParse_NonMatchingFirstByte(t *testing.T) {
	got := Parse([]byte{0xff, 0x00, 0x00}, Config{EnableTLS: true, EnableHTTP: true, EnableHTTP2: true})
	if got.Hit {
		t.Fatalf("binary payload produced %+v", got)
	}
}

// ------------------- Benchmark -------------------

func BenchmarkParseTLS_ClientHello(b *testing.B) {
	payload := buildClientHello(b, "www.youtube.com")
	cfg := Config{EnableTLS: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Parse(payload, cfg)
	}
}