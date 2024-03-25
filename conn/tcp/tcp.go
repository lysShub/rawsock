package tcp

import (
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type closeCallback func(raddr netip.AddrPort, isn uint32) error

type closedTCPInfo struct {
	DeleteAt time.Time
	Raddr    netip.AddrPort
	ISN      uint32
}

// todo: tun implement

func tcpSynSizeRange(ipv4 bool) (min, max int) {
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
