package tcp

import (
	"net/netip"
	"time"
)

type closeCallback func(raddr netip.AddrPort, isn uint32) error

type closedTCPInfo struct {
	DeleteAt time.Time
	Raddr    netip.AddrPort
	ISN      uint32
}

// todo: tun implement
