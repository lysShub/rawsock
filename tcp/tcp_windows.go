//go:build windows
// +build windows

package tcp

import (
	"net/netip"

	"github.com/lysShub/rawsock"
	"github.com/lysShub/rawsock/tcp/divert"
)

func Listen(laddr netip.AddrPort, opts ...rawsock.Option) (rawsock.Listener, error) {
	return divert.Listen(laddr, opts...)
}

func Connect(laddr, raddr netip.AddrPort, opts ...rawsock.Option) (rawsock.RawConn, error) {
	return divert.Connect(laddr, raddr, opts...)
}
