package udp

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func SizeRange(ipv4 bool) (min, max int) {
	min, max = header.UDPMinimumSize, header.UDPMinimumSize
	if ipv4 {
		min += header.IPv4MinimumSize
		max += header.IPv4MaximumHeaderSize
	} else {
		min += header.IPv6MinimumSize
		max += header.IPv6MinimumSize
	}
	return
}

type CloseCallback func(netip.AddrPort) error
