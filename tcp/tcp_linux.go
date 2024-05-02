//go:build linux
// +build linux

package tcp

import (
	"net/netip"

	"github.com/lysShub/rawsock"
	"github.com/lysShub/rawsock/tcp/raw"
)

func Listen(laddr netip.AddrPort, opts ...rawsock.Option) (rawsock.Listener, error) {
	return raw.Listen(laddr, opts...)
}

func Connect(laddr, raddr netip.AddrPort, opts ...rawsock.Option) (rawsock.RawConn, error) {
	return raw.Connect(laddr, raddr, opts...)
}
