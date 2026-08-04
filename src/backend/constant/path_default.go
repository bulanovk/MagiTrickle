//go:build !entware && !openwrt && !ubuntu

package constant

const (
	AppConfigDir = "/etc/magitrickle"
	AppShareDir  = "/usr/share/magitrickle"
	AppStateDir  = "/var/lib/magitrickle"
	PIDPath      = "/var/run/magitrickle.pid"
	SockPath     = "/var/run/magitrickle.sock"
	PasswdFile   = "/etc/passwd"
	ShadowFile   = "/etc/shadow"

	DefaultDNSUpstreamAddress = "127.0.0.1"
	DefaultDNSUpstreamPort    = 53

	DefaultShowAllInterfaces = false
)
