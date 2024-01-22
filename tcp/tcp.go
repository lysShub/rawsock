package tcp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal"
)

func listenLocal(laddr netip.AddrPort) (*net.TCPListener, netip.AddrPort, error) {
	if !laddr.IsValid() {
		laddr = netip.AddrPortFrom(relraw.LocalAddr(), laddr.Port())
	}
	if !internal.ValidateListenAddr(laddr.Addr()) {
		return nil, netip.AddrPort{}, fmt.Errorf("invalid listen address %s", laddr.Addr().String())
	}

	addr := &net.TCPAddr{IP: laddr.Addr().AsSlice(), Port: int(laddr.Port())}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	return l, laddr, nil
}

type CloseCallback func(raddr netip.AddrPort) error
