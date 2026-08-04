package sniffer

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// IP protocol numbers we care about. Only TCP is sniffed in v1; UDP
// is left for QUIC/DoQ support in a later phase.
const (
	protoTCP uint8 = 6
	protoUDP uint8 = 17
)

// IPv6 extension header protocol numbers (RFC 8200 §4). Hop-by-Hop,
// Routing and Destination Options share the (nextHeader, hdrExtLen)
// layout and can be skipped generically. Fragment, AH and ESP have
// different layouts — we fail closed on those rather than guess.
const (
	extHopByHop  uint8 = 0
	extRouting   uint8 = 43
	extFragment  uint8 = 44
	extESP       uint8 = 50
	extAH        uint8 = 51
	extDestOpts  uint8 = 60
	extNoNextHdr uint8 = 59
)

// parsedIP is the minimal output of the IP header parser: the
// destination address and the offset where transport-layer data
// begins. IPv4 and IPv6 are unified so the sniffer callback can
// dispatch without branching on address family.
type parsedIP struct {
	Src            net.IP
	Dst            net.IP
	TransportProto uint8
	PayloadOffset  int // byte offset of transport header within packet
}

// parseIPPacket extracts the destination IP, transport protocol
// number, and payload offset from a raw IP packet (IPv4 or IPv6).
// Returns a non-nil error for any input that is neither v4 nor v6, or
// that is too short to contain the fixed header — the sniffer logs
// these as parse_failures and silently ACCEPTs the packet.
func parseIPPacket(pkt []byte) (parsedIP, error) {
	if len(pkt) < 1 {
		return parsedIP{}, fmt.Errorf("empty packet")
	}
	switch pkt[0] >> 4 {
	case 4:
		return parseIPv4(pkt)
	case 6:
		return parseIPv6(pkt)
	default:
		return parsedIP{}, fmt.Errorf("unknown IP version %d", pkt[0]>>4)
	}
}

func parseIPv4(pkt []byte) (parsedIP, error) {
	hdr, err := ipv4.ParseHeader(pkt)
	if err != nil {
		return parsedIP{}, fmt.Errorf("ipv4: %w", err)
	}
	return parsedIP{
		Src:            append(net.IP(nil), hdr.Src...),
		Dst:            append(net.IP(nil), hdr.Dst...),
		TransportProto: uint8(hdr.Protocol),
		PayloadOffset:  hdr.Len,
	}, nil
}

func parseIPv6(pkt []byte) (parsedIP, error) {
	hdr, err := ipv6.ParseHeader(pkt)
	if err != nil {
		return parsedIP{}, fmt.Errorf("ipv6: %w", err)
	}
	dst := append(net.IP(nil), hdr.Dst...)
	src := append(net.IP(nil), hdr.Src...)
	// x/net parses only the fixed 40-byte header, so walk extension
	// headers ourselves until TCP/UDP. Hop-by-Hop/Routing/Destination
	// Options share the (nextHeader, hdrExtLen) layout with length in
	// 8-octet units excluding the first 8 octets, i.e. (extLen+1)*8.
	nextHeader := uint8(hdr.NextHeader)
	offset := 40
	for nextHeader != protoTCP && nextHeader != protoUDP {
		switch nextHeader {
		case extHopByHop, extRouting, extDestOpts:
			if offset+8 > len(pkt) {
				return parsedIP{}, fmt.Errorf("ipv6 ext header truncated at %d", offset)
			}
			nextHeader = pkt[offset]
			offset += (int(pkt[offset+1]) + 1) * 8
			if offset > len(pkt) {
				return parsedIP{}, fmt.Errorf("ipv6 ext header overruns packet")
			}
		default:
			// Fragment/AH/ESP, NoNextHeader or anything unknown: fail
			// closed — the packet is logged as a parse failure and
			// ACCEPTed without sniffing.
			return parsedIP{}, fmt.Errorf("ipv6 unsupported next header %d", nextHeader)
		}
	}
	return parsedIP{
		Src:            src,
		Dst:            dst,
		TransportProto: nextHeader,
		PayloadOffset:  offset,
	}, nil
}

// TCP header parsing lives inline in nfqueue_common.go — we only
// need src/dst port and the payload offset, so wrapping a three-line
// computation in a struct-returning helper was more ceremony than
// benefit.
