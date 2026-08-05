package sniffer

import "runtime"

// runtimeGOOS is a tiny indirection so tests can run identically on every
// platform without leaking the runtime package across the whole codebase.
func runtimeGOOS() string {
	return runtime.GOOS
}