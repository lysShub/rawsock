package relraw

import (
	"net"
	"net/netip"
)

type Listener interface {
	Accept() (RawConn, error)
}

type RawConn interface {
	Close() error

	// read ip packet
	Read(ip []byte) (n int, err error)

	// write tcp/udp packet
	Write(b []byte) (n int, err error)
	WriteReservedIPHeader(ip []byte) (n int, err error)

	Inject(b []byte) (n int, err error)
	InjectReservedIPHeader(ip []byte) (n int, err error)

	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	LocalAddrAddrPort() netip.AddrPort
	RemoteAddrAddrPort() netip.AddrPort
}

func LocalAddr() netip.Addr {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}

func LocalAddr6() netip.Addr {
	c, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	if err != nil {
		return netip.Addr{}
	}
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}
