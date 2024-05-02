//go:build linux
// +build linux

package tcp

import (
	"net/netip"

	"github.com/lysShub/sockit"
	"github.com/lysShub/sockit/tcp/raw"
)

func Listen(laddr netip.AddrPort, opts ...sockit.Option) (sockit.Listener, error) {
	return raw.Listen(laddr, opts...)
}

func Connect(laddr, raddr netip.AddrPort, opts ...sockit.Option) (sockit.RawConn, error) {
	return raw.Connect(laddr, raddr, opts...)
}
