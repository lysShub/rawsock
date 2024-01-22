package internal

import (
	"net/netip"
)

func ValidateListenAddr(addr netip.Addr) bool {
	if addr.IsLoopback() ||
		addr == netip.IPv4Unspecified() ||
		addr == netip.IPv6Unspecified() {
		// 1. not support loopback packet
		// 2. IP Zero means listen all nic, unsupported.
		return false
	}
	return true
}

func ValideConnectAddrs(loc, dst netip.Addr) bool {
	if !ValidateListenAddr(loc) {
		return false
	}
	if !ValidateListenAddr(loc) {
		return false
	}

	return loc != dst
}
