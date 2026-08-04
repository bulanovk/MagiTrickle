package sniffer

import (
	"net"
	"testing"
)

// ipv4Header builds a minimal IPv4 header with the given dst and
// protocol. Returned slice is exactly 20 bytes (no options).
func ipv4Header(dst net.IP, proto uint8) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, IHL 5
	h[1] = 0x00 // DSCP/ECN
	h[2] = 0x00 // total length (irrelevant here)
	h[3] = 0x00
	h[8] = 64 // TTL
	h[9] = proto
	copy(h[12:16], net.ParseIP("10.0.0.1").To4())
	copy(h[16:20], dst.To4())
	return h
}

// ipv6Header builds a minimal IPv6 header with the given dst and
// next-header value. Returned slice is exactly 40 bytes.
func ipv6Header(dst net.IP, next uint8) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	h[6] = next
	copy(h[8:24], net.ParseIP("fe80::1"))
	copy(h[24:40], dst.To16())
	return h
}

// tcpSegment builds a minimal TCP header + small payload. dstPort and
// payload are appended after the 20-byte fixed header (data offset
// = 5).
func tcpSegment(dstPort uint16, payload []byte) []byte {
	h := make([]byte, 20)
	h[12] = 0x50 // data offset = 5 (20 bytes), reserved = 0
	h[13] = 0x18 // PSH+ACK flags
	h[2] = byte(dstPort >> 8)
	h[3] = byte(dstPort & 0xff)
	return append(h, payload...)
}

func TestParseIPPacket_IPv4TCP(t *testing.T) {
	dst := net.ParseIP("1.2.3.4").To4()
	hdr := ipv4Header(dst, protoTCP)
	tcp := tcpSegment(443, []byte{0x16, 0x03, 0x01, 0x00, 0x05})

	ip, err := parseIPPacket(append(hdr, tcp...))
	if err != nil {
		t.Fatalf("parseIPPacket: %v", err)
	}
	if !ip.Dst.Equal(dst) {
		t.Errorf("Dst = %v, want %v", ip.Dst, dst)
	}
	if ip.TransportProto != protoTCP {
		t.Errorf("TransportProto = %d, want TCP", ip.TransportProto)
	}
	if ip.PayloadOffset != 20 {
		t.Errorf("PayloadOffset = %d, want 20", ip.PayloadOffset)
	}
	if !ip.Src.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("Src = %v, want 10.0.0.1", ip.Src)
	}
}

func TestParseIPPacket_IPv6TCP(t *testing.T) {
	dst := net.ParseIP("2001:db8::1")
	hdr := ipv6Header(dst, protoTCP)
	tcp := tcpSegment(443, []byte{0x16})

	ip, err := parseIPPacket(append(hdr, tcp...))
	if err != nil {
		t.Fatalf("parseIPPacket: %v", err)
	}
	if !ip.Dst.Equal(dst) {
		t.Errorf("Dst = %v, want %v", ip.Dst, dst)
	}
	if ip.TransportProto != protoTCP {
		t.Errorf("TransportProto = %d, want TCP", ip.TransportProto)
	}
	if ip.PayloadOffset != 40 {
		t.Errorf("PayloadOffset = %d, want 40", ip.PayloadOffset)
	}
	if !ip.Src.Equal(net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) {
		t.Errorf("Src = %v, want fe80::1", ip.Src)
	}
}

func TestParseIPPacket_UnknownVersion(t *testing.T) {
	_, err := parseIPPacket([]byte{0x50, 0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for version=5, got nil")
	}
}

func TestParseIPPacket_TruncatedIPv4(t *testing.T) {
	_, err := parseIPPacket([]byte{0x45, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated IPv4")
	}
}

func TestParseIPPacket_TruncatedIPv6(t *testing.T) {
	_, err := parseIPPacket([]byte{0x60, 0x00, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated IPv6")
	}
}

func TestParseIPPacket_IPv6HopByHopExtLenZero(t *testing.T) {
	// Regression: a Hop-by-Hop header with Hdr Ext Len = 0 (8 bytes
	// total) must still advance the offset — the old walker computed
	// 8 + (extLen-1)*8 = 0 and looped forever.
	dst := net.ParseIP("2001:db8::1")
	hdr := ipv6Header(dst, extHopByHop)
	ext := []byte{protoTCP, 0, 0, 0, 0, 0, 0, 0} // next=TCP, extLen=0
	tcp := tcpSegment(443, []byte{0x16})

	pkt := append(append(hdr, ext...), tcp...)
	ip, err := parseIPPacket(pkt)
	if err != nil {
		t.Fatalf("parseIPPacket: %v", err)
	}
	if ip.TransportProto != protoTCP {
		t.Errorf("TransportProto = %d, want TCP", ip.TransportProto)
	}
	if ip.PayloadOffset != 48 {
		t.Errorf("PayloadOffset = %d, want 48 (40 + 8)", ip.PayloadOffset)
	}
}

func TestParseIPPacket_IPv6DestOptsSkipsCorrectLength(t *testing.T) {
	// Hdr Ext Len = 1 means (1+1)*8 = 16 bytes total.
	dst := net.ParseIP("2001:db8::1")
	hdr := ipv6Header(dst, extDestOpts)
	ext := make([]byte, 16)
	ext[0] = protoTCP
	ext[1] = 1
	tcp := tcpSegment(443, []byte{0x16})

	pkt := append(append(hdr, ext...), tcp...)
	ip, err := parseIPPacket(pkt)
	if err != nil {
		t.Fatalf("parseIPPacket: %v", err)
	}
	if ip.PayloadOffset != 56 {
		t.Errorf("PayloadOffset = %d, want 56 (40 + 16)", ip.PayloadOffset)
	}
}

func TestParseIPPacket_IPv6FragmentFailsClosed(t *testing.T) {
	dst := net.ParseIP("2001:db8::1")
	hdr := ipv6Header(dst, extFragment)
	frag := make([]byte, 8) // next=TCP, reserved=0, offset/flags, ident
	frag[0] = protoTCP
	tcp := tcpSegment(443, []byte{0x16})

	pkt := append(append(hdr, frag...), tcp...)
	if _, err := parseIPPacket(pkt); err == nil {
		t.Fatal("expected fail-closed error for Fragment header, got nil")
	}
}
