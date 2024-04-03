package conn

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// todo: set MSG_TRUNC flag
func CompleteCheck(ipv4 bool, ip []byte) bool {
	if ipv4 {
		return header.IPv4(ip).TotalLength() == uint16(len(ip))
	} else {
		return header.IPv6(ip).PayloadLength()+header.IPv6MinimumSize == uint16(len(ip))
	}
}

type ErrNotUsedPort int

func (e ErrNotUsedPort) Error() string {
	return fmt.Sprintf("port %d not bind", int(e))
}
