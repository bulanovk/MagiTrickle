package sniffer

import (
	"testing"

	"golang.org/x/net/http2/hpack"
)

// encodeHTTP2Headers runs the canonical hpack encoder over the given
// fields and returns the wire bytes. testutil_test.go keeps these
// helpers separate so the per-protocol test files stay readable.
// Accepts testing.TB so the helper works from both tests and
// benchmarks.
func encodeHTTP2Headers(tb testing.TB, fields map[string]string) []byte {
	tb.Helper()
	var buf []byte
	enc := hpack.NewEncoder(&byteWriter{buf: &buf})
	// Stable order makes test failures deterministic; hpack requires
	// pseudo-headers (those starting with ':') to come first, so we
	// sort accordingly.
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	// Pseudo-headers first.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if pseudoLess(keys[j], keys[i]) {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		if err := enc.WriteField(hpack.HeaderField{Name: k, Value: fields[k]}); err != nil {
			tb.Fatalf("hpack encode: %v", err)
		}
	}
	return buf
}

// pseudoLess puts pseudo-headers (those starting with ':') before
// regular ones, otherwise alphabetical.
func pseudoLess(a, b string) bool {
	aPseudo := len(a) > 0 && a[0] == ':'
	bPseudo := len(b) > 0 && b[0] == ':'
	if aPseudo != bPseudo {
		return aPseudo
	}
	return a < b
}

// byteWriter satisfies io.Writer for hpack.NewEncoder without
// dragging bytes.Buffer into every test signature.
type byteWriter struct {
	buf *[]byte
}

func (w *byteWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}