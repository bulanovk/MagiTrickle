package constant

import (
	"time"

	"magitrickle/models"
)

var DefaultAppConfig = models.AppConfig{
	DNSProxy: models.AppConfigDNSProxy{
		Host:            models.AppConfigDNSProxyServer{Address: "[::]", Port: 3553},
		Upstream:        models.AppConfigDNSProxyServer{Address: DefaultDNSUpstreamAddress, Port: DefaultDNSUpstreamPort},
		DisableRemap53:  false,
		DisableFakePTR:  false,
		DisableDropAAAA: false,
		MaxIdleConns:    10,
		MaxConcurrent:   100,
		Timeout:         5000 * time.Millisecond,
	},
	HTTPWeb: models.AppConfigHTTPWeb{
		Enabled: true,
		Auth: models.AppConfigAuth{
			Enabled: false,
		},
		Host: models.AppConfigHTTPWebServer{
			Address: "[::]",
			Port:    8080,
		},
		Skin: "default",
	},
	Netfilter: models.AppConfigNetfilter{
		IPTables: models.AppConfigIPTables{
			ChainPrefix: "MT_",
		},
		IPSet: models.AppConfigIPSet{
			TablePrefix:   "mt_",
			AdditionalTTL: 1 * time.Hour,
		},
		DisableIPv4:         false,
		DisableIPv6:         false,
		StartMarkTableIndex: 0x4D616769, // Magi
	},
	Link:              []string{"br0"},
	ShowAllInterfaces: DefaultShowAllInterfaces,
	LogLevel:          "info",
	SNISniffer: models.AppConfigSNISniffer{
		Enabled:       false,
		QueueNum:      0,
		MaxQueueLen:   1024,
		MaxPacketLen:  0xFFFF,
		EnableTLS:     true,
		EnableHTTP:    true,
		EnableHTTP2:   true,
		AdditionalTTL: 1 * time.Hour,
	},
}

var (
	Version = "unattached"
)
