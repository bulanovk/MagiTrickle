package config

import "time"

type App struct {
	HTTPWeb           *HTTPWeb    `yaml:"httpWeb"`
	DNSProxy          *DNSProxy   `yaml:"dnsProxy"`
	Netfilter         *Netfilter  `yaml:"netfilter"`
	SNISniffer        *SNISniffer `yaml:"sniSniffer"`
	Link              *[]string   `yaml:"link"`
	ShowAllInterfaces *bool       `yaml:"showAllInterfaces"`
	LogLevel          *string     `yaml:"logLevel"`
}

type HTTPWeb struct {
	Enabled *bool          `yaml:"enabled"`
	Auth    *Auth          `yaml:"auth"`
	Host    *HTTPWebServer `yaml:"host"`
	Skin    *string        `yaml:"skin"`
}

type Auth struct {
	Enabled *bool `yaml:"enabled"`
}

type HTTPWebServer struct {
	Address *string `yaml:"address"`
	Port    *uint16 `yaml:"port"`
}

type DNSProxy struct {
	Host            *DNSProxyServer `yaml:"host"`
	Upstream        *DNSProxyServer `yaml:"upstream"`
	DisableRemap53  *bool           `yaml:"disableRemap53"`
	DisableFakePTR  *bool           `yaml:"disableFakePTR"`
	DisableDropAAAA *bool           `yaml:"disableDropAAAA"`
	MaxIdleConns    *uint           `yaml:"maxIdleConns"`
	MaxConcurrent   *uint           `yaml:"maxConcurrent"`
	Timeout         *time.Duration  `yaml:"timeout"`
}

type DNSProxyServer struct {
	Address *string `yaml:"address"`
	Port    *uint16 `yaml:"port"`
}

type Netfilter struct {
	IPTables            *IPTables `yaml:"iptables"`
	IPSet               *IPSet    `yaml:"ipset"`
	DisableIPv4         *bool     `yaml:"disableIPv4"`
	DisableIPv6         *bool     `yaml:"disableIPv6"`
	StartMarkTableIndex *uint32   `yaml:"startMarkTableIndex"`
}

type IPTables struct {
	ChainPrefix *string `yaml:"chainPrefix"`
}

type IPSet struct {
	TablePrefix   *string        `yaml:"tablePrefix"`
	AdditionalTTL *time.Duration `yaml:"additionalTTL"`
}

// SNISniffer holds optional first-packet domain attribution settings.
// Parses TLS ClientHello and HTTP Host / :authority from TCP flows whose
// destination IP is not yet covered by any active ipset, catching DoH/DoT
// traffic and ECH-protected flows that bypass DNS-MITM.
type SNISniffer struct {
	Enabled       *bool          `yaml:"enabled"`
	QueueNum      *uint16        `yaml:"queueNum"`
	MaxQueueLen   *uint32        `yaml:"maxQueueLen"`
	MaxPacketLen  *uint32        `yaml:"maxPacketLen"`
	EnableTLS     *bool          `yaml:"enableTLS"`
	EnableHTTP    *bool          `yaml:"enableHTTP"`
	EnableHTTP2   *bool          `yaml:"enableHTTP2"`
	AllowedPorts  *[]uint16      `yaml:"allowedPorts"`
	AdditionalTTL *time.Duration `yaml:"additionalTTL"`
	// LogDNSMismatch enables INFO logging when SNI and DNS attribute
	// the same IP to different domains. Diagnostic only; default false.
	LogDNSMismatch *bool `yaml:"logDNSMismatch"`
}
