package internal

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func MinIPPacketSize(addr netip.Addr, proto tcpip.TransportProtocolNumber) int {
	var minSize int
	switch proto {
	case header.TCPProtocolNumber:
		minSize += header.TCPMinimumSize
	case header.UDPProtocolNumber:
		minSize += header.UDPMinimumSize
	case header.ICMPv4ProtocolNumber:
		minSize += header.ICMPv4MinimumSize
	case header.ICMPv6ProtocolNumber:
		minSize += header.ICMPv6MinimumSize
	default:
		panic("")
	}

	if addr.Is4() {
		minSize += header.IPv4MinimumSize
	} else {
		minSize += header.IPv6MinimumSize
	}
	return minSize
}
