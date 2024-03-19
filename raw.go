package rsocket

import (
	"context"
	"net"
	"net/netip"
)

type Listener interface {
	Accept() (RawConn, error)

	// todo:
	// AcceptCtx(ctx context.Context)(RawConn, error)

	Addr() netip.AddrPort

	Close() error
}

type RawConn interface {
	Close() error

	// Read read ip packet from remote address
	Read(ip []byte) (n int, err error)

	// ReadCtx read tcp/udp/icmp packet from remote address
	ReadCtx(ctx context.Context, p *Packet) (err error)

	// Write write ip packet to remote
	Write(ip []byte) (n int, err error)

	// WriteCtx write tcp/udp/icmp packet to remote address, tcp/udp packet
	// should set checksum that without pseudo checksum
	WriteCtx(ctx context.Context, p *Packet) (err error)

	// Inject inject ip packet to local address
	Inject(ip []byte) (err error)

	// InjectCtx inject tcp/udp/icmp packet to local address, tcp/udp packet
	// should set checksum that without pseudo checksum
	InjectCtx(ctx context.Context, p *Packet) (err error)

	LocalAddr() netip.AddrPort
	RemoteAddr() netip.AddrPort
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
