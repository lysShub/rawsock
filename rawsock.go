package rawsock

import (
	"context"
	"net"
	"net/netip"

	"github.com/lysShub/netkit/packet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const Overhead = header.IPv4MinimumSize // todo: ipv6

type Listener interface {

	// Accept transport connection
	//
	// Example:
	//   for {
	//       conn, err := l.Accept()
	//       if err != nil {
	//           if errorx.Temporary(err) {
	//               log.Warn(err, ...)
	//               continue
	//           }
	//           return  err
	//       }
	//       ...
	//   }
	Accept() (RawConn, error)

	// todo:
	// AcceptCtx(ctx context.Context)(RawConn, error)

	Addr() netip.AddrPort

	Close() error
}

// todo: support raw rw
type RawConn interface {
	Close() error

	// ReadCtx read tcp/udp/icmp packet from remote address
	Read(ctx context.Context, pkt *packet.Packet) (err error)
	// ReadRaw(ctx context.Context, ip *packet.Packet) (err error)

	// WriteCtx write tcp/udp/icmp packet to remote address
	Write(ctx context.Context, pkt *packet.Packet) (err error)
	// WriteRaw(ctx context.Context, ip *packet.Packet) (err error)

	// InjectCtx inject tcp/udp/icmp packet to local address
	Inject(ctx context.Context, pkt *packet.Packet) (err error)
	// InjectRaw(ctx context.Context, ip *packet.Packet) (err error)

	LocalAddr() netip.AddrPort
	RemoteAddr() netip.AddrPort
}

func LocalAddr() netip.Addr {
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: []byte{8, 8, 8, 8}, Port: 53})
	if err != nil {
		panic(err)
	}
	defer c.Close()
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}

func LocalAddr6() netip.Addr {
	c, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP("::FFFF:8.8.8.8"), Port: 53})
	if err != nil {
		panic(err)
	}
	defer c.Close()
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}
