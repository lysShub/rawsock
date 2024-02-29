package tcp

import (
	"net/netip"
)

type CloseCallback func(raddr netip.AddrPort, isn uint32) error
