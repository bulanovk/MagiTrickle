//go:build linux

// nfqueue_linux.go — sole NFQUEUE implementation. Pure-Go via
// florianl/go-nfqueue (mdlayher/netlink). The previous cgo backend
// over libnetfilter_queue / libmnl has been removed.
package sniffer

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/mdlayher/netlink"
	"github.com/rs/zerolog/log"
)

type linuxSniffer struct {
	cfg        Config
	startedAt  time.Time
	counters   counters
	hooks      atomic.Pointer[Hooks]
	closed     atomic.Bool
	tcpFlowBuf sync.Map
	shutdown   chan struct{}
	shutdownMu sync.Mutex
	nf         *nfqueue.Nfqueue
}

func newLinuxSniffer(cfg Config) *linuxSniffer {
	return &linuxSniffer{cfg: cfg, shutdown: make(chan struct{})}
}

func (n *linuxSniffer) Start(ctx context.Context, hooks Hooks) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	probe := ProbeKernelModules()
	if !probe.Available {
		return fmt.Errorf("%w (nfqueue=%v ipset=%v conntrack=%v)",
			ErrKernelModulesMissing, probe.NFQueue, probe.IPSet, probe.Conntrack)
	}

	n.startedAt = time.Now()
	n.counters.startedAt = n.startedAt
	n.hooks.Store(&hooks)
	n.closed.Store(false)

	queueNum := n.cfg.QueueNum
	if queueNum == 0 {
		queueNum = 0
	}
	maxQueueLen := n.cfg.MaxQueueLen
	if maxQueueLen == 0 {
		maxQueueLen = 1024
	}
	maxPacketLen := n.cfg.MaxPacketLen
	if maxPacketLen == 0 {
		maxPacketLen = 0xFFFF
	}

	config := nfqueue.Config{
		NfQueue:      uint16(queueNum),
		MaxPacketLen: uint32(maxPacketLen),
		MaxQueueLen:  uint32(maxQueueLen),
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		return fmt.Errorf("sniffer: nfqueue.Open: %w", err)
	}
	n.nf = nf
	defer func() {
		_ = nf.Close()
		n.nf = nil
	}()

	// Avoid ENOBUFS storms under load.
	_ = nf.SetOption(netlink.NoENOBUFS, true)

	gcStop := startFlowGC(ctx, &n.tcpFlowBuf)
	defer gcStop()

	// Bridge ctx.Done() / Stop() → cancel the recv context.
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
		case <-n.shutdown:
		}
		cancel()
	}()

	fn := func(a nfqueue.Attribute) int {
		if a.Payload != nil {
			handlePacketShared(&n.counters, &n.tcpFlowBuf, &n.hooks, n.cfg, *a.Payload)
		}
		if a.PacketID != nil && n.nf != nil {
			_ = n.nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		}
		return 0
	}
	errFn := func(e error) int {
		log.Warn().Err(e).Msg("sniffer: nfqueue error")
		return 0
	}

	if err := nf.RegisterWithErrorFunc(ctx2, fn, errFn); err != nil {
		n.closed.Store(true)
		if err == context.Canceled && ctx.Err() == nil {
			return nil
		}
		return fmt.Errorf("sniffer: RegisterWithErrorFunc: %w", err)
	}
	// RegisterWithErrorFunc only spawns the socket-callback goroutine and
	// returns nil immediately; block here on ctx2 so the deferred
	// nf.Close() only runs once the goroutine has exited.
	<-ctx2.Done()
	n.closed.Store(true)
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (n *linuxSniffer) Stop() error {
	markStopped(&n.closed, n.shutdown, &n.shutdownMu)
	return nil
}

func (n *linuxSniffer) Stats() Stats {
	return n.counters.snapshot()
}
