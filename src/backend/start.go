package magitrickle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"magitrickle/api"
	"magitrickle/sniffer"
	"magitrickle/utils/dnsMITMProxy"
	"magitrickle/utils/iptables"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// Start запускает приложение (ядро)
func (a *App) Start(ctx context.Context) (err error) {
	if !a.enabled.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer a.enabled.Store(false)

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic: %v\n%s\n", r, debug.Stack())
			err = errors.New(fmt.Sprintf("panic: %v", r))
		}
	}()

	a.setupLogging()

	a.dnsMITM = dnsMITMProxy.NewDNSMITMProxy(
		net.JoinHostPort(a.config.DNSProxy.Upstream.Address, strconv.Itoa(int(a.config.DNSProxy.Upstream.Port))),
		a.config.DNSProxy.MaxIdleConns,
		a.config.DNSProxy.MaxConcurrent,
		a.config.DNSProxy.Timeout,
	)
	a.dnsMITM.RequestHook = a.dnsRequestHook
	a.dnsMITM.ResponseHook = a.dnsResponseHook
	defer func() {
		if a.dnsMITM != nil {
			_ = a.dnsMITM.Close()
		}
	}()

	a.recordsCache = recordsCache.New()
	a.recordsCache.StartCleanup(ctx, 30*time.Second)

	nfh, err := netfilterTools.New(a.config.Netfilter.IPTables.ChainPrefix, a.config.Netfilter.IPSet.TablePrefix, a.config.Netfilter.DisableIPv4, a.config.Netfilter.DisableIPv6, a.config.Netfilter.StartMarkTableIndex)
	if err != nil {
		return fmt.Errorf("netfilter helper init fail: %w", err)
	}
	a.nfHelper = nfh

	// SNI sniffer kernel probe. The sniffer itself is started later in
	// Start(); here we only verify that the kernel has the modules it
	// needs so we can log a useful message before any rules are installed.
	probe := sniffer.ProbeKernelModules()
	sniEnabled := a.config.SNISniffer.Enabled && probe.Available
	if a.config.SNISniffer.Enabled {
		if probe.Available {
			log.Info().
				Bool("nfqueue", probe.NFQueue).
				Bool("ipset", probe.IPSet).
				Bool("conntrack", probe.Conntrack).
				Msg("SNI sniffer: probe OK")

			a.sniRules = nfh.SNIRules(a.config.SNISniffer.QueueNum, a.config.SNISniffer.AllowedPorts)
			if err := a.sniRules.Enable(); err != nil {
				log.Warn().Err(err).Msg("SNI sniffer: failed to install MT_SNI chain; falling back to disabled")
				sniEnabled = false
				a.sniRules = nil
			} else {
				defer func() { _ = a.sniRules.Disable() }()
			}
		} else {
			log.Warn().
				Bool("nfqueue", probe.NFQueue).
				Bool("ipset", probe.IPSet).
				Bool("conntrack", probe.Conntrack).
				Msg("SNI sniffer: required kernel modules missing; sniffer disabled")
		}
	} else if probe.Available {
		log.Debug().
			Msg("SNI sniffer: feature disabled in config")
	}
	// Build the sniffer (NoOp on non-Linux, on missing modules, or
	// when disabled). The actual Start() is launched as a background
	// goroutine after newCtx exists so cancellation flows through it.
	a.sniffer = sniffer.New(sniffer.Config{
		Enabled:       sniEnabled,
		QueueNum:      a.config.SNISniffer.QueueNum,
		MaxQueueLen:   a.config.SNISniffer.MaxQueueLen,
		MaxPacketLen:  a.config.SNISniffer.MaxPacketLen,
		EnableTLS:     a.config.SNISniffer.EnableTLS,
		EnableHTTP:    a.config.SNISniffer.EnableHTTP,
		EnableHTTP2:   a.config.SNISniffer.EnableHTTP2,
		AllowedPorts:  a.config.SNISniffer.AllowedPorts,
		AdditionalTTL: a.config.SNISniffer.AdditionalTTL,
	})
	snifferHooks := newSNIMatcher(a)

	for _, ipt := range []*iptables.IPTables{a.nfHelper.IPTables4, a.nfHelper.IPTables6} {
		if ipt == nil {
			continue
		}
		ipt.RegisterChainPatch("filter", "FORWARD")
		ipt.RegisterChainPatch("mangle", "PREROUTING")
		ipt.RegisterChainPatch("nat", "PREROUTING")
		ipt.RegisterChainPatch("nat", "POSTROUTING")
	}

	if err := a.nfHelper.CleanIPTables(); err != nil {
		return fmt.Errorf("failed to clear iptables: %w", err)
	}

	linkUpdateChannel, linkUpdateDone, err := subscribeLinkUpdates()
	if err != nil {
		return err
	}
	defer close(linkUpdateDone)

	addrUpdateChannel, addrUpdateDone, err := subscribeAddrUpdates()
	if err != nil {
		return err
	}
	defer close(addrUpdateDone)

	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if sniEnabled {
		go func() {
			if err := a.sniffer.Start(newCtx, snifferHooks); err != nil {
				log.Warn().Err(err).Msg("SNI sniffer stopped with error")
			}
		}()
		defer func() {
			if err := a.sniffer.Stop(); err != nil {
				log.Warn().Err(err).Msg("SNI sniffer stop")
			}
		}()
	}
	errChan := make(chan error)

	httpServer, err := api.SetupHTTP(a, errChan)
	if err != nil {
		return fmt.Errorf("setup http fail: %w", err)
	}
	defer httpServer.Close()

	unixServer, err := api.SetupUnixSocket(a, errChan)
	if err != nil {
		return fmt.Errorf("setup unix socket fail: %w", err)
	}
	defer unixServer.Close()

	a.startDNSListeners(newCtx, errChan)

	var interfaceAddrs []netlink.Addr
	if len(a.config.Link) == 0 {
		// Fallback when no explicit link is configured (e.g. Ubuntu server/desktop):
		// enumerate all non-loopback interfaces so port-remap still produces DNAT
		// rules. On router platforms (OpenWrt/Entware), link is always set explicitly.
		links, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("failed to list links: %w", err)
		}
		for _, link := range links {
			if link.Attrs().Name == "lo" {
				continue
			}
			addrs, err := netlink.AddrList(link, nl.FAMILY_ALL)
			if err != nil {
				continue
			}
			interfaceAddrs = append(interfaceAddrs, addrs...)
		}
	} else {
		for _, linkName := range a.config.Link {
			link, err := netlink.LinkByName(linkName)
			if err != nil {
				return fmt.Errorf("failed to find link %s: %w", linkName, err)
			}
			linkAddrList, err := netlink.AddrList(link, nl.FAMILY_ALL)
			if err != nil {
				return fmt.Errorf("failed to list address of interface %s: %w", linkName, err)
			}
			interfaceAddrs = append(interfaceAddrs, linkAddrList...)
		}
	}

	if !a.config.DNSProxy.DisableRemap53 {
		a.dnsOverrider = a.nfHelper.PortRemap("DNSOR", 53, a.config.DNSProxy.Host.Port, interfaceAddrs)
		if err := a.dnsOverrider.Enable(); err != nil {
			return fmt.Errorf("failed to override DNS: %v", err)
		}
		defer func() {
			_ = a.dnsOverrider.Disable()
		}()
	}

	for _, group := range a.ruleSetSnapshot() {
		if err := group.Enable(); err != nil {
			return fmt.Errorf("failed to enable group: %w", err)
		}
		if err := group.Sync(); err != nil {
			return fmt.Errorf("failed to sync group: %w", err)
		}
	}
	defer func() {
		for _, group := range a.ruleSetSnapshot() {
			_ = group.Disable()
		}
	}()

	go a.StartSubscriptionAutoUpdate(newCtx)

	for {
		select {
		case event := <-linkUpdateChannel:
			a.handleLink(event)
		case event := <-addrUpdateChannel:
			a.handleAddr(event)
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

func (a *App) ForceCommitIPTables() error {
	if a.nfHelper == nil {
		return nil
	}

	if a.nfHelper.IPTables4 != nil {
		err := a.nfHelper.IPTables4.Commit()
		if err != nil {
			return fmt.Errorf("failed to commit iptables rules: %w", err)
		}
	}

	if a.nfHelper.IPTables6 != nil {
		err := a.nfHelper.IPTables6.Commit()
		if err != nil {
			return fmt.Errorf("failed to commit iptables rules: %w", err)
		}
	}

	return nil
}

func (a *App) setupLogging() {
	switch a.config.LogLevel {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	case "nolevel":
		zerolog.SetGlobalLevel(zerolog.NoLevel)
	case "disabled":
		zerolog.SetGlobalLevel(zerolog.Disabled)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
