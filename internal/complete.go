package internal

import "gvisor.dev/gvisor/pkg/tcpip/header"

func CompleteCheck(ipv4 bool, ip []byte) bool {
	if ipv4 {
		return header.IPv4(ip).TotalLength() == uint16(len(ip))
	} else {
		return header.IPv6(ip).PayloadLength()+header.IPv6MinimumSize == uint16(len(ip))
	}
}
