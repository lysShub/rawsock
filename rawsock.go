package rawsock

import (
	"net"
	"net/netip"

	"github.com/lysShub/netkit/packet"
)

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

// todo: 支持raw读写
// todo: 删除Read会将tail作为容量进行读取
// todo: 支持deadline
type RawConn interface {

	// Read read tcp/udp/icmp packet from remote address
	Read(pkt *packet.Packet) (err error)
	// ReadRaw(ip *packet.Packet) (err error)

	// Write write tcp/udp/icmp packet to remote address
	Write(pkt *packet.Packet) (err error)
	// WriteRaw( ip *packet.Packet) (err error)

	// Inject inject tcp/udp/icmp packet to local address
	Inject(pkt *packet.Packet) (err error)

	LocalAddr() netip.AddrPort
	RemoteAddr() netip.AddrPort
	Close() error
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
