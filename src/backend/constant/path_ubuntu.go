//go:build ubuntu

package constant

const (
	AppConfigDir = "/etc/magitrickle"
	AppShareDir  = "/usr/share/magitrickle"
	AppStateDir  = "/var/lib/magitrickle"
	PIDPath      = "/var/run/magitrickle.pid"
	SockPath     = "/var/run/magitrickle.sock"
	PasswdFile   = "/etc/passwd"
	ShadowFile   = "/etc/shadow"

	// DefaultDNSUpstreamAddress points at systemd-resolved's stub resolver,
	// which listens on 127.0.0.53:53 on Ubuntu 24.04 by default.
	DefaultDNSUpstreamAddress = "127.0.0.53"
	DefaultDNSUpstreamPort    = 53

	// DefaultShowAllInterfaces is true on Ubuntu because Ethernet/WiFi interfaces
	// are not point-to-point; the PPPoE-based filterManaged() would hide them all.
	DefaultShowAllInterfaces = true
)
