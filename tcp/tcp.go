package tcp

import (
	"net/netip"
)

type CloseCallback func(raddr netip.AddrPort) error
