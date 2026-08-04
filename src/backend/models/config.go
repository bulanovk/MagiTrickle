package models

import "time"

type AppConfig struct {
	HTTPWeb           AppConfigHTTPWeb
	DNSProxy          AppConfigDNSProxy
	Netfilter         AppConfigNetfilter
	SNISniffer        AppConfigSNISniffer
	Link              []string
	ShowAllInterfaces bool
	LogLevel          string
}

type AppConfigHTTPWeb struct {
	Enabled bool
	Auth    AppConfigAuth
	Host    AppConfigHTTPWebServer
	Skin    string
}

type AppConfigAuth struct {
	Enabled bool
}

type AppConfigHTTPWebServer struct {
	Address string
	Port    uint16
}

type AppConfigDNSProxy struct {
	Host            AppConfigDNSProxyServer
	Upstream        AppConfigDNSProxyServer
	DisableRemap53  bool
	DisableFakePTR  bool
	DisableDropAAAA bool
	MaxIdleConns    uint
	MaxConcurrent   uint
	Timeout         time.Duration
}

type AppConfigDNSProxyServer struct {
	Address string
	Port    uint16
}

type AppConfigNetfilter struct {
	IPTables            AppConfigIPTables
	IPSet               AppConfigIPSet
	DisableIPv4         bool
	DisableIPv6         bool
	StartMarkTableIndex uint32
}

type AppConfigIPTables struct {
	ChainPrefix string
}

type AppConfigIPSet struct {
	TablePrefix   string
	AdditionalTTL time.Duration
}

// AppConfigSNISniffer is the runtime representation of the sniffer config.
// Fields use plain types because defaults are filled by LoadConfig from
// constant.DefaultAppConfig before unmarshalling user overrides.
type AppConfigSNISniffer struct {
	Enabled       bool
	QueueNum      uint16
	MaxQueueLen   uint32
	MaxPacketLen  uint32
	EnableTLS     bool
	EnableHTTP    bool
	EnableHTTP2   bool
	AllowedPorts  []uint16
	AdditionalTTL time.Duration
	// LogDNSMismatch gates the SNI/DNS disagreement diagnostic log.
	LogDNSMismatch bool
}
