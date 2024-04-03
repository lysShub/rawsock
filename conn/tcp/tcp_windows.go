//go:build windows
// +build windows

package tcp

import (
	"net/netip"

	"github.com/lysShub/sockit/conn"
	"github.com/lysShub/sockit/conn/tcp/divert"
)

func Listen(laddr netip.AddrPort, opts ...conn.Option) (conn.Listener, error) {
	return divert.Listen(laddr, opts...)
}

func Connect(laddr, raddr netip.AddrPort, opts ...conn.Option) (conn.RawConn, error) {
	return divert.Connect(laddr, raddr, opts...)
}
