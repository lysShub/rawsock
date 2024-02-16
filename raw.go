package relraw

import (
	"context"
	"net"
	"net/netip"
)

type Listener interface {
	Accept() (RawConn, error)

	// todo: next support
	// AcceptBy(filter []bpf.Instruction)(RawConn,error)
}

type RawConn interface {
	Close() error

	// Read read ip packet from remote address
	Read(ip []byte) (n int, err error)

	// ReadCtx read ip packet from remote address
	ReadCtx(ctx context.Context, ip []byte) (n int, err error)

	// Write write tcp/udp/icmp packet to remote address, tcp/udp packet
	// should set checksum that without pseudo checksum
	Write(b []byte) (n int, err error)

	// WriteReserved Write tcp/udp/icmp with prefix reserved n bytes
	WriteReserved(b []byte, n int) (err error)

	// WriteRaw write ip packet to remote address
	WriteRaw(ip []byte) (err error)

	// todo: Inject 意义不明
	// Inject inject tcp/udp/icmp packet to local address, tcp/udp packet
	// should set checksum that without pseudo checksum
	Inject(b []byte) (err error)

	// InjectReserved Inject tcp/udp/icmp with prefix reserved bytes
	InjectReserved(ip []byte, reserved int) (err error)

	// InjectRaw inject ip packet to local address
	InjectRaw(ip []byte) (err error)

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
