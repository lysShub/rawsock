package tcp

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type ID struct {
	Local  netip.AddrPort
	Remote netip.AddrPort // remote address
	ISN    uint32
}

type CloseCallback func(ID) error

func SizeRange(ipv4 bool) (min, max int) {
	min, max = header.TCPMinimumSize, header.TCPHeaderMaximumSize
	if ipv4 {
		min += header.IPv4MinimumSize
		max += header.IPv4MaximumHeaderSize
	} else {
		min += header.IPv6MinimumSize
		max += header.IPv6MinimumSize
	}
	return
}
