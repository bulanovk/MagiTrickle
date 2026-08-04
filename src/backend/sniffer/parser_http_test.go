package sniffer

import (
	"testing"
)

// ------------------- HTTP/1.1 -------------------

func TestParseHTTP1_GETWithHost(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: test\r\n" +
		"\r\n")
	cfg := Config{EnableHTTP: true}
	got := Parse(payload, cfg)
	if !got.Hit {
		t.Fatal("expected OK=true")
	}
	if got.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", got.Domain)
	}
	if got.Protocol != ProtocolHTTP {
		t.Errorf("Protocol = %q, want http", got.Protocol)
	}
}

func TestParseHTTP1_HOSTWithLeadingSpace(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost:   www.example.com   \r\n\r\n")
	cfg := Config{EnableHTTP: true}
	got := Parse(payload, cfg)
	if !got.Hit || got.Domain != "www.example.com" {
		t.Fatalf("got %+v, want domain=www.example.com", got)
	}
}

func TestParseHTTP1_HOSTCaseInsensitive(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nhost: example.org\r\n\r\n")
	cfg := Config{EnableHTTP: true}
	got := Parse(payload, cfg)
	if !got.Hit || got.Domain != "example.org" {
		t.Fatalf("got %+v, want domain=example.org", got)
	}
}

func TestParseHTTP1_NoHostHeader(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n")
	cfg := Config{EnableHTTP: true}
	got := Parse(payload, cfg)
	if got.Hit {
		t.Fatalf("expected OK=false without Host header, got %+v", got)
	}
}

func TestParseHTTP1_HostWithPort(t *testing.T) {
	// The sniffer feeds the raw Host header to ruleSetSnapshot. The
	// rule engine handles host:port via existing domain logic, so we
	// just confirm we don't truncate the port.
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n")
	cfg := Config{EnableHTTP: true}
	got := Parse(payload, cfg)
	if !got.Hit || got.Domain != "example.com:8443" {
		t.Fatalf("got %+v, want domain=example.com:8443", got)
	}
}

func TestParseHTTP1_DisabledReturnsFalse(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	cfg := Config{EnableHTTP: false}
	got := Parse(payload, cfg)
	if got.Hit {
		t.Fatalf("got %+v, want OK=false when EnableHTTP=false", got)
	}
}

func TestParseHTTP1_POST(t *testing.T) {
	payload := []byte("POST /submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n")
	cfg := Config{EnableHTTP: true}
	got := Parse(payload, cfg)
	if !got.Hit || got.Domain != "api.example.com" {
		t.Fatalf("got %+v, want domain=api.example.com", got)
	}
}

// ------------------- HTTP/2 -------------------

func TestParseHTTP2_PrefaceWithAuthority(t *testing.T) {
	// Use the live hpack encoder to produce a single HEADERS frame
	// with :method=GET, :path=/, :scheme=https, :authority=example.com.
	encoded := encodeHTTP2Headers(t, map[string]string{
		":method":    "GET",
		":path":      "/",
		":scheme":    "https",
		":authority": "h2.example.com",
	})
	frame := append([]byte{}, byte(0x00), byte(0x00), byte(len(encoded)), 0x01, 0x04, 0x00, 0x00, 0x00, 0x01)
	frame = append(frame, encoded...)
	payload := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), frame...)

	cfg := Config{EnableHTTP2: true}
	got := Parse(payload, cfg)
	if !got.Hit {
		t.Fatal("expected OK=true")
	}
	if got.Domain != "h2.example.com" {
		t.Errorf("Domain = %q, want h2.example.com", got.Domain)
	}
	if got.Protocol != ProtocolHTTP2 {
		t.Errorf("Protocol = %q, want http2", got.Protocol)
	}
}

func TestParseHTTP2_NoAuthority(t *testing.T) {
	// HEADERS frame without :authority should not produce a result.
	encoded := encodeHTTP2Headers(t, map[string]string{
		":method": "GET",
		":path":   "/",
		":scheme": "https",
	})
	frame := append([]byte{}, byte(0x00), byte(0x00), byte(len(encoded)), 0x01, 0x04, 0x00, 0x00, 0x00, 0x01)
	frame = append(frame, encoded...)
	payload := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), frame...)

	cfg := Config{EnableHTTP2: true}
	got := Parse(payload, cfg)
	if got.Hit {
		t.Fatalf("expected OK=false without :authority, got %+v", got)
	}
}

func TestParseHTTP2_BadPreface(t *testing.T) {
	cfg := Config{EnableHTTP2: true}
	got := Parse([]byte("GET / HTTP/1.1\r\n\r\n"), cfg)
	if got.Hit {
		t.Fatalf("HTTP/1.1 payload matched HTTP/2 dispatcher, got %+v", got)
	}
}

// ------------------- Benchmarks -------------------

func BenchmarkParseHTTP1_GET(b *testing.B) {
	payload := []byte("GET /index.html HTTP/1.1\r\n" +
		"Host: www.youtube.com\r\n" +
		"User-Agent: test\r\n" +
		"\r\n")
	cfg := Config{EnableHTTP: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Parse(payload, cfg)
	}
}

func BenchmarkParseHTTP2_Preface(b *testing.B) {
	encoded := encodeHTTP2Headers(b, map[string]string{
		":method":    "GET",
		":path":      "/",
		":scheme":    "https",
		":authority": "www.youtube.com",
	})
	frame := append([]byte{}, byte(0x00), byte(0x00), byte(len(encoded)), 0x01, 0x04, 0x00, 0x00, 0x00, 0x01)
	frame = append(frame, encoded...)
	payload := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), frame...)
	cfg := Config{EnableHTTP2: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Parse(payload, cfg)
	}
}