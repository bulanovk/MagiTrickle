//go:build linux

// Package sniffer — Linux NFQUEUE shared code.
//
// The Linux implementation lives in nfqueue_linux.go and is built on
// florianl/go-nfqueue (pure-Go over mdlayher/netlink). An earlier cgo
// variant over libnetfilter_queue / libmnl has been removed — it was
// no longer needed once the pure-Go backend was verified to work on
// Ubuntu 24.04 / kernel 6.8.x. The types, counters, and packet-flow
// helpers defined here are shared with the non-Linux fallback in
// nfqueue_other.go.
package sniffer

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type tcpFlowKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
}

type tcpFlowState struct {
	buf        []byte
	firstSeen  time.Time
	lastSeen   time.Time
	dstIP      net.IP
	dstPort    uint16
	seqInitial uint32
}

const flowTimeout = 10 * time.Second
const flowGCInterval = 1 * time.Second
const maxFlowBuf = 64 * 1024

var ErrKernelModulesMissing = errors.New("sniffer: required kernel modules missing")

func makeFlowKey(ip parsedIP, srcPort, dstPort uint16) tcpFlowKey {
	var k tcpFlowKey
	src16 := ip.Src.To16()
	if src16 == nil {
		src16 = net.IPv4zero.To16()
	}
	copy(k.SrcIP[:], src16)
	dst16 := ip.Dst.To16()
	if dst16 == nil {
		dst16 = net.IPv4zero.To16()
	}
	copy(k.DstIP[:], dst16)
	k.SrcPort = srcPort
	k.DstPort = dstPort
	return k
}

func handlePacketShared(rec *counters, flows *sync.Map, hooks *atomic.Pointer[Hooks], cfg Config, payload []byte) {
	ip, err := parseIPPacket(payload)
	if err != nil {
		rec.recordPacket(false, false, true)
		return
	}
	if ip.TransportProto != protoTCP {
		rec.recordPacket(false, true, false)
		return
	}
	// Inline TCP header read: src/dst port and payload offset. The
	// data-offset nibble is at byte 12 of the TCP header; a malformed
	// header (truncated or out-of-range data offset) is logged as a
	// parse failure and the packet is ACCEPTed without sniffing.
	transport := ip.PayloadOffset
	if transport+20 > len(payload) {
		rec.recordPacket(false, false, true)
		return
	}
	tcpSrcPort := binary.BigEndian.Uint16(payload[transport : transport+2])
	tcpDstPort := binary.BigEndian.Uint16(payload[transport+2 : transport+4])
	dataOff := int(payload[transport+12]>>4) * 4
	if dataOff < 20 || transport+dataOff > len(payload) {
		rec.recordPacket(false, false, true)
		return
	}
	tcpPayloadOffset := transport + dataOff
	tcpPayload := payload[tcpPayloadOffset:]
	if len(tcpPayload) == 0 {
		rec.recordEmpty()
		return
	}
	key := makeFlowKey(ip, tcpSrcPort, tcpDstPort)
	if existing, ok := flows.Load(key); ok {
		st := existing.(*tcpFlowState)
		st.lastSeen = time.Now()
		if len(st.buf)+len(tcpPayload) > maxFlowBuf {
			flows.Delete(key)
			rec.recordPacket(false, false, true)
			return
		}
		st.buf = append(st.buf, tcpPayload...)
		if parseFlowBufferShared(rec, hooks, cfg, key, st) {
			rec.recordStitched()
			flows.Delete(key)
			return
		}
		diagnosticDump(st.buf, "stitched-miss")
		flows.Delete(key)
		rec.recordPacket(false, true, false)
		return
	}
	res := Parse(tcpPayload, cfg)
	if res.Hit && res.Domain != "" {
		rec.recordPacket(true, false, false)
		fireHookShared(hooks, res, ip.Dst)
		return
	}
	if len(tcpPayload) >= 1 && tcpPayload[0] == 0x16 {
		st := &tcpFlowState{
			buf:        append([]byte(nil), tcpPayload...),
			firstSeen:  time.Now(),
			lastSeen:   time.Now(),
			dstIP:      append([]byte(nil), ip.Dst...),
			dstPort:    tcpDstPort,
			seqInitial: binary.BigEndian.Uint32(payload[transport+4 : transport+8]),
		}
		flows.Store(key, st)
		rec.recordPacket(false, true, false)
		return
	}
	rec.recordPacket(false, true, false)
}

func parseFlowBufferShared(rec *counters, hooks *atomic.Pointer[Hooks], cfg Config, key tcpFlowKey, st *tcpFlowState) bool {
	res := Parse(st.buf, cfg)
	if !res.Hit || res.Domain == "" {
		return false
	}
	rec.recordPacket(true, false, false)
	fireHookShared(hooks, res, st.dstIP)
	return true
}

func fireHookShared(hooks *atomic.Pointer[Hooks], res SniffResult, dst net.IP) {
	hooksPtr := hooks.Load()
	if hooksPtr == nil {
		return
	}
	h := *hooksPtr
	h.OnDomain(res.Domain, dst, res.Protocol)
}

func evictStaleFlows(flows *sync.Map) {
	cutoff := time.Now().Add(-flowTimeout)
	flows.Range(func(k, v any) bool {
		st := v.(*tcpFlowState)
		if st.lastSeen.Before(cutoff) {
			flows.Delete(k)
		}
		return true
	})
}

func startFlowGC(ctx context.Context, flows *sync.Map) (stop func()) {
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(flowGCInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				evictStaleFlows(flows)
			case <-stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stopCh) })
		<-done
	}
}

func markStopped(closed *atomic.Bool, shutdown chan struct{}, mu *sync.Mutex) {
	closed.Store(true)
	mu.Lock()
	select {
	case <-shutdown:
	default:
		close(shutdown)
	}
	mu.Unlock()
}
