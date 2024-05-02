//go:build windows
// +build windows

package tcp

import (
	"net/netip"

	"github.com/lysShub/sockit"
	"github.com/lysShub/sockit/tcp/divert"
)

func Listen(laddr netip.AddrPort, opts ...sockit.Option) (sockit.Listener, error) {
	return divert.Listen(laddr, opts...)
}

func Connect(laddr, raddr netip.AddrPort, opts ...sockit.Option) (sockit.RawConn, error) {
	return divert.Connect(laddr, raddr, opts...)
}
