//go:build linux
// +build linux

package tcp

import (
	"net/netip"

	"github.com/lysShub/sockit/conn"
	"github.com/lysShub/sockit/conn/tcp/raw"
)

func Listen(laddr netip.AddrPort, opts ...conn.Option) (conn.Listener, error) {
	return raw.Listen(laddr, opts...)
}

func Connect(laddr, raddr netip.AddrPort, opts ...conn.Option) (conn.RawConn, error) {
	return raw.Connect(laddr, raddr, opts...)
}
