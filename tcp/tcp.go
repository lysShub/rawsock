package tcp

import (
	"net/netip"
	"time"
)

type CloseCallback func(raddr netip.AddrPort, isn uint32) error

type ClosedConnInfo struct {
	DeleteAt time.Time
	Raddr    netip.AddrPort
	ISN      uint32
}
