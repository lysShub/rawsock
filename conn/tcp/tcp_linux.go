package tcp

import (
	"net/netip"

	"github.com/lysShub/rsocket/conn"
)

func Listen(laddr netip.AddrPort, opts ...conn.Option) (conn.Listener, error) {
	return ListenEth(laddr, opts...)
}

func Connect(laddr, raddr netip.AddrPort, opts ...conn.Option) (conn.RawConn, error) {
	return ConnectEth(laddr, raddr, opts...)
}
