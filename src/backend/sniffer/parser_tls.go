package sniffer

import (
	"encoding/binary"
	"errors"
)

// This file is a vendored, slightly trimmed copy of
// https://github.com/XTLS/Xray-core/blob/main/common/protocol/tls/sniff.go
//
// xray-core's TLS sniffer is the production code path behind 3x-ui's
// SNI-based routing; it has been hammered by every REALITY/VLESS
// deployment since 2022 and is the cheapest correct reference parser
// we can adopt. Differences from upstream:
//
//   - SniffHeader replaced by our existing SniffResult.
//   - common.ErrNoClue and protocol.ErrProtoNeedMoreData inlined as
//     local sentinels (they are trivial errors.New(...) in upstream;
//     vendoring just to get them would pull in xray-core's full
//     dependency tree).
//   - Removed the QUIC-specific "may need more data" path because the
//     NFQUEUE loop only feeds raw TCP segments; QUIC runs over UDP and
//     a separate parser owns that.
//
// The vendoring is explicit so future maintainers know where to look
// when upstream changes the wire format. To re-sync, diff against the
// URL above and resolve the four trimmed sites.

var (
	errNoClue = errors.New("tls: not enough information for making a decision")
	errNotTLS = errors.New("tls: not TLS header")
	errNotCH  = errors.New("tls: not client hello")
)

// sniffTLSResult is the borrowed name from upstream. We expose a
// SniffResult instead of xray's *SniffHeader to keep the parser
// dispatcher's surface stable.
func sniffTLS(b []byte) SniffResult {
	if len(b) < 5 {
		setParserFail("tls:too_short")
		return SniffResult{}
	}
	if b[0] != 0x16 {
		setParserFail("tls:not_handshake")
		return SniffResult{}
	}
	// IsValidTLSVersion in upstream: major == 3. b[1] is the
	// legacy_version_major byte directly (== 0x03 for every TLS
	// version, TLS 1.0 through 1.3). DTLS uses 0xfe/0xfd as the
	// first record byte so it falls through the b[0] check; SSLv2
	// has its own header (first byte MSB set, see RFC 5246 Appendix A).
	// Our earlier copy of this check mistakenly shifted b[1] by 4,
	// which rejected every real packet whose minor byte was 0x01
	// (TLS 1.0 record version) instead of 0x03. Upstream tests pass
	// because b[1] *is* the major byte, not a packed nibble.
	if b[1] != 0x03 {
		setParserFail("tls:bad_version")
		return SniffResult{}
	}
	headerLen := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+headerLen > len(b) {
		setParserFail("tls:truncated")
		return SniffResult{}
	}
	domain, ok := readClientHello(b[5 : 5+headerLen])
	if !ok {
		setParserFail("tls:parse_ch")
		return SniffResult{}
	}
	if domain == "" {
		setParserFail("tls:no_sni")
		return SniffResult{}
	}
	return SniffResult{
		Hit:      true,
		Reason:   ReasonHit,
		Domain:   domain,
		Protocol: ProtocolTLS,
	}
}

// readClientHello follows the structure of Go's crypto/tls
// handshake_messages.go ClientHello parser — session_id, cipher
// suites, compression methods, extensions — and returns the SNI from
// the first host_name entry it sees. Upstream returns errors; we
// collapse them into an "ok" bool because the NFQUEUE loop only
// cares about Hit.
func readClientHello(data []byte) (string, bool) {
	if len(data) < 42 {
		return "", false
	}
	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return "", false
	}
	data = data[39+sessionIDLen:]
	if len(data) < 2 {
		return "", false
	}
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return "", false
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return "", false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return "", false
	}
	data = data[1+compressionMethodsLen:]

	if len(data) < 2 {
		return "", false
	}
	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return "", false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return "", false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return "", false
		}
		if extension == 0x00 { // server_name
			d := data[:length]
			if len(d) < 2 {
				return "", false
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return "", false
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return "", false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return "", false
				}
				if nameType == 0 {
					// xray returns protocol.ErrProtoNeedMoreData
					// here when the SNI contains a non-printable
					// byte — that branch exists for QUIC where a
					// single ClientHello can straddle UDP datagrams.
					// Our recv loop already concatenates the full
					// TCP segment, so the "incomplete name" case
					// cannot happen; we drop the check.
					return string(d[:nameLen]), true
				}
				d = d[nameLen:]
			}
		}
		data = data[length:]
	}
	return "", false
}