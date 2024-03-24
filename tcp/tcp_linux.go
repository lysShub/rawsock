package tcp

import (
	"net/netip"

	"github.com/lysShub/rsocket"
)

func Listen(laddr netip.AddrPort, opts ...rsocket.Option) (rsocket.Listener, error) {
	return ListenEth(laddr, opts...)
}

func Connect(laddr, raddr netip.AddrPort, opts ...rsocket.Option) (rsocket.RawConn, error) {
	return ConnectEth(laddr, raddr, opts...)
}
