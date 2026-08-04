package sniffer

import (
	"bytes"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// http2ClientPreface is the 24-byte connection preface every HTTP/2
// client must send on a new connection (RFC 7540 §3.5).
var http2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// http2 frame types we recognise.
const (
	http2FrameData    uint8 = 0x0
	http2FrameHeaders uint8 = 0x1
)

// http2 frame flags.
const (
	http2FlagEndStream uint8 = 0x1
	http2FlagPadded    uint8 = 0x8
)

// isHTTP1Token reports whether b looks like the start of a valid
// HTTP/1.1 method token (RFC 7230 §3.1.1: only US-ASCII letters).
// The check guards against false positives like 'P' from binary
// protocols that the dispatcher would otherwise route to parseHTTP1.
func isHTTP1Token(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// parseHTTP1Request scans a TCP payload for the Host header. It walks
// the request line + header block up to the first \r\n\r\n (or the end
// of the buffer if the headers are still arriving). Field name
// comparison is case-insensitive per RFC 7230 §3.2; the value is
// stripped of leading/trailing OWS before being returned.
//
// The parser tolerates malformed input by returning OK=false instead
// of erroring — the sniffer then accepts the packet without touching
// the route table.
func parseHTTP1Request(payload []byte) SniffResult {
	if len(payload) < 4 {
		setParserFail("http1:bad_method")
		return SniffResult{}
	}

	// Defensive: the dispatcher already checked the first byte is one
	// of the method tokens, but a corrupted capture could still slip
	// through. Confirm the second byte is also ASCII letter/space.
	if !isHTTP1Token(payload[1]) && payload[1] != ' ' {
		setParserFail("http1:bad_method")
		return SniffResult{}
	}

	// Bound the scan: never look past 8 KiB of headers, the practical
	// upper bound for any well-behaved client.
	const headerLimit = 8 * 1024
	headers := payload
	if end := bytes.Index(payload, []byte("\r\n\r\n")); end >= 0 {
		headers = payload[:end]
	} else if len(headers) > headerLimit {
		headers = headers[:headerLimit]
	}

	// Skip the request line (everything up to the first \r\n).
	if i := bytes.Index(headers, []byte("\r\n")); i >= 0 {
		headers = headers[i+2:]
	} else {
		// No header block — nothing to extract.
		setParserFail("http1:no_headers")
		return SniffResult{}
	}

	for len(headers) > 0 {
		lineEnd := bytes.Index(headers, []byte("\r\n"))
		var line []byte
		if lineEnd < 0 {
			line = headers
			headers = nil
		} else {
			line = headers[:lineEnd]
			headers = headers[lineEnd+2:]
		}
		if len(line) == 0 {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if !strings.EqualFold(string(line[:colon]), "host") {
			continue
		}
		value := bytes.TrimSpace(line[colon+1:])
		if len(value) == 0 {
			setParserFail("http1:empty_host")
			return SniffResult{}
		}
		return SniffResult{
			Hit:      true,
			Reason:   ReasonHit,
			Domain:   string(value),
			Protocol: ProtocolHTTP,
		}
	}
		setParserFail("http1:no_host")
	return SniffResult{}
}

// parseHTTP2Initial reads the client preface and walks frames until
// it finds a HEADERS frame containing :authority. We deliberately
// ignore the stream ID — a v1 sniffer only needs the first request
// on any stream to populate the routing table, and HTTP/2 clients
// typically have only one stream active at connection start.
//
// The HPACK decoder state table is allocated per-call. The default
// 4 KiB dynamic table is what RFC 7540 mandates, and the cost of
// allocating it per packet is negligible compared to the alternative
// of sharing state across goroutines (which would require locking).
func parseHTTP2Initial(payload []byte) SniffResult {
	if !bytes.HasPrefix(payload, http2ClientPreface) {
		setParserFail("http2:no_preface")
		return SniffResult{}
	}
	body := payload[len(http2ClientPreface):]

	for len(body) >= 9 {
		length := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
		frameType := body[3]
		flags := body[4]
		// streamID := uint32(body[5])<<24 | uint32(body[6])<<16 |
		//             uint32(body[7])<<8 | uint32(body[8])
		// streamID &= 0x7fffffff

		if 9+length > len(body) {
			break
		}
		frame := body[9 : 9+length]
		body = body[9+length:]

		if frameType == http2FrameHeaders {
			frameBody := frame
			if flags&http2FlagPadded != 0 {
				if len(frameBody) < 1 {
					break
				}
				padLen := int(frameBody[0])
				if 1+padLen > len(frameBody) {
					break
				}
				frameBody = frameBody[1 : len(frameBody)-padLen]
			}
			authority, ok := decodeH2Authority(frameBody)
			if ok {
				return SniffResult{
					Hit:      true,
					Reason:   ReasonHit,
					Domain:   authority,
					Protocol: ProtocolHTTP2,
				}
			}
		}

		if flags&http2FlagEndStream != 0 {
			break
		}
	}
	setParserFail("http2:miss")
	return SniffResult{}
}

// decodeH2Authority decodes a HEADERS frame body with HPACK and
// returns the :authority pseudo-header value, if present.
func decodeH2Authority(encoded []byte) (string, bool) {
	dec := hpack.NewDecoder(4096, nil)
	fields, err := dec.DecodeFull(encoded)
	if err != nil {
		setParserFail("http2:hpack_err")
		return "", false
	}
	for _, f := range fields {
		if f.Name == ":authority" && f.Value != "" {
			return f.Value, true
		}
	}
	setParserFail("http2:no_authority")
	return "", false
}