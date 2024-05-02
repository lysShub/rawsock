package test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/go-ping/ping"
	"github.com/pkg/errors"

	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/sockit"
	"github.com/lysShub/sockit/helper/ipstack"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func calcChecksum() func(ip header.IPv4) header.IPv4 {
	var (
		first     = true
		calcIP    = true
		calcTrans = true
	)
	return func(ip header.IPv4) header.IPv4 {
		if first {
			calcIP = !ip.IsChecksumValid()

			psum := header.PseudoHeaderChecksum(
				ip.TransportProtocol(),
				ip.SourceAddress(),
				ip.DestinationAddress(),
				ip.PayloadLength(),
			)
			calcTrans = checksum.Checksum(ip.Payload(), psum) != 0xffff
			first = false
		}

		if calcIP || calcTrans {
			CalcChecksum(ip)
		}
		return ip
	}
}

func CalcChecksum(ip header.IPv4) {
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	psum := header.PseudoHeaderChecksum(
		ip.TransportProtocol(),
		ip.SourceAddress(),
		ip.DestinationAddress(),
		ip.PayloadLength(),
	)
	switch ip.TransportProtocol() {
	case header.TCPProtocolNumber:
		tcp := header.TCP(ip.Payload())
		tcp.SetChecksum(0)
		tcp.SetChecksum(^checksum.Checksum(tcp, psum))
	case header.UDPProtocolNumber:
		udp := header.UDP(ip.Payload())
		udp.SetChecksum(0)
		udp.SetChecksum(^checksum.Checksum(udp, psum))
	default:
		panic("")
	}

}

func BuildTCPSync(t require.TestingT, laddr, raddr netip.AddrPort) header.TCP {
	var b = make(header.TCP, header.TCPMinimumSize)
	b.Encode(&header.TCPFields{
		SrcPort:    uint16(laddr.Port()),
		DstPort:    uint16(raddr.Port()),
		SeqNum:     rand.Uint32(),
		AckNum:     rand.Uint32(),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 83,
		Checksum:   0,
	})

	sum := header.PseudoHeaderChecksum(
		tcp.ProtocolNumber,
		Address(laddr.Addr()), Address(raddr.Addr()),
		uint16(len(b)),
	)
	sum = checksum.Checksum(b, sum)
	b.SetChecksum(^sum)

	require.True(t,
		b.IsChecksumValid(
			tcpip.AddrFromSlice(laddr.Addr().AsSlice()),
			tcpip.AddrFromSlice(raddr.Addr().AsSlice()),
			checksum.Checksum(b.Payload(), 0),
			uint16(len(b.Payload())),
		),
	)

	return b
}

func ValidIP(t require.TestingT, ip []byte) {
	var iphdr header.Network
	var totalLen int
	switch header.IPVersion(ip) {
	case 4:
		ip := header.IPv4(ip)
		require.True(t, ip.IsChecksumValid())
		iphdr = ip
		totalLen = int(ip.TotalLength())
	case 6:
		iphdr = header.IPv6(ip)
		totalLen = int(header.IPv6(ip).PayloadLength()) + header.IPv6MinimumSize
	default:
		panic(hex.Dump(ip))
	}
	require.Equal(t, totalLen, len(ip))

	pseudoSum1 := header.PseudoHeaderChecksum(
		iphdr.TransportProtocol(),
		iphdr.SourceAddress(),
		iphdr.DestinationAddress(),
		0,
	)

	switch iphdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		ValidTCP(t, iphdr.Payload(), pseudoSum1)
	case header.UDPProtocolNumber:
		ValidUDP(t, iphdr.Payload(), pseudoSum1)
	case header.ICMPv4ProtocolNumber:
		icmp := header.ICMPv4(iphdr.Payload())
		sum := checksum.Checksum(icmp, 0)
		require.Equal(t, uint16(0xffff), sum)
	default:
		panic(iphdr.TransportProtocol())
	}
}

func ValidTCP(t require.TestingT, tcp header.TCP, pseudoSum1 uint16) {
	psum := checksum.Combine(pseudoSum1, uint16(len(tcp)))
	sum := checksum.Checksum(tcp, psum)
	require.Equal(t, uint16(0xffff), sum)
}
func ValidUDP(t require.TestingT, udp header.UDP, pseudoSum1 uint16) {
	psum := checksum.Combine(pseudoSum1, uint16(len(udp)))
	sum := checksum.Checksum(udp, psum)
	require.Equal(t, uint16(0xffff), sum)
}

func BuildRawTCP(t require.TestingT, laddr, raddr netip.AddrPort, payload []byte) header.IPv4 {
	require.True(t, laddr.Addr().Is4())

	iptcp := header.IPv4MinimumSize + header.TCPMinimumSize

	totalSize := iptcp + len(payload)
	var b = make([]byte, totalSize)
	copy(b[iptcp:], payload)

	ts := uint32(time.Now().UnixNano())
	tcphdr := header.TCP(b[header.IPv4MinimumSize:])
	tcphdr.Encode(&header.TCPFields{
		SrcPort:    uint16(laddr.Port()),
		DstPort:    uint16(raddr.Port()),
		SeqNum:     501 + ts,
		AckNum:     ts,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck | header.TCPFlagPsh,
		WindowSize: 83,
		Checksum:   0,
	})

	s, err := ipstack.New(laddr.Addr(), raddr.Addr(), header.TCPProtocolNumber)
	require.NoError(t, err)
	p := packet.Make().Append(b).SetHead(s.Size())
	s.AttachOutbound(p)

	// psoSum := s.AttachHeader(b, header.TCPProtocolNumber)

	// tcphdr.SetChecksum(^checksum.Checksum(tcphdr, psoSum))

	require.True(t, header.IPv4(b).IsChecksumValid())
	require.True(t,
		tcphdr.IsChecksumValid(
			tcpip.AddrFromSlice(laddr.Addr().AsSlice()),
			tcpip.AddrFromSlice(raddr.Addr().AsSlice()),
			checksum.Checksum(tcphdr.Payload(), 0),
			uint16(len(tcphdr.Payload())),
		),
	)

	return b
}

func BuildICMP(t require.TestingT, src, dst netip.Addr, typ header.ICMPv4Type, msg []byte) header.IPv4 {
	require.Zero(t, len(msg)%4)

	var iphdr = make(header.IPv4, 28+len(msg))
	iphdr.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(iphdr)),
		ID:             uint16(rand.Uint32()),
		Flags:          0,
		FragmentOffset: 0,
		TTL:            128,
		Protocol:       uint8(header.ICMPv4ProtocolNumber),
		Checksum:       0,
		SrcAddr:        tcpip.AddrFromSlice(src.AsSlice()),
		DstAddr:        tcpip.AddrFromSlice(dst.AsSlice()),
	})
	iphdr.SetChecksum(^checksum.Checksum(iphdr[:iphdr.HeaderLength()], 0))
	require.True(t, iphdr.IsChecksumValid())

	icmphdr := header.ICMPv4(iphdr.Payload())
	icmphdr.SetType(typ)
	icmphdr.SetCode(0)
	icmphdr.SetChecksum(0)
	icmphdr.SetIdent(0x0005)
	icmphdr.SetSequence(0x0001)
	copy(icmphdr.Payload(), msg)
	icmphdr.SetChecksum(^checksum.Checksum(icmphdr, 0))

	ValidIP(t, iphdr)
	return iphdr
}

func PingOnce(t *testing.T, dst string) {
	pinger, err := ping.NewPinger(dst)
	require.NoError(t, err)
	pinger.SetPrivileged(true)
	pinger.Timeout = time.Millisecond
	pinger.Count = 1
	require.NoError(t, pinger.Run())
}

func StripIP(ip []byte) []byte {
	switch header.IPVersion(ip) {
	case 4:
		return header.IPv4(ip).Payload()
	case 6:
		return header.IPv6(ip).Payload()
	default:
		return nil
	}
}

func RandPort() uint16 {
	p := uint16(rand.Uint32())
	if p < 1024 {
		p += 1536
	} else if p > 0xffff-64 {
		p -= 128
	}
	return p
}

// maybe not valid ip
func RandIP() netip.Addr {

	b := binary.BigEndian.AppendUint32(nil, rand.Uint32())

	return netip.AddrFrom4([4]byte(b))
}

func TCPAddr(a netip.AddrPort) *net.TCPAddr {
	return &net.TCPAddr{IP: a.Addr().AsSlice(), Port: int(a.Port())}
}

func UDPAddr(a netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{IP: a.Addr().AsSlice(), Port: int(a.Port())}
}
func Address(a netip.Addr) tcpip.Address {
	return tcpip.AddrFromSlice(a.AsSlice())
}
func FullAddress(a netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{
		Addr: Address(a.Addr()),
		Port: a.Port(),
	}
}
func FullAddressPtr(a netip.AddrPort) *tcpip.FullAddress {
	addr := FullAddress(a)
	return &addr
}

type ustack struct {
	addr  tcpip.Address
	stack *stack.Stack

	link *channel.Endpoint
}

func NewUstack(t require.TestingT, addr netip.Addr, handleLocal bool) *ustack {
	require.True(t, addr.Is4())

	laddr := tcpip.AddrFromSlice(addr.AsSlice())
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        handleLocal,
	})
	l := channel.New(4, 1500, "")

	const nicid tcpip.NICID = 1234
	err := st.CreateNIC(nicid, l)
	require.Nil(t, err)
	st.AddProtocolAddress(nicid, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: laddr.WithPrefix(),
	}, stack.AddressProperties{})
	st.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicid}})

	var u = &ustack{
		addr:  laddr,
		stack: st,
		link:  l,
	}
	return u
}

// ValidPingPongConn if set udpMss, means conn is datagram
func ValidPingPongConn(t require.TestingT, s *rand.Rand, conn net.Conn, size int, udpMss ...int) {
	var buf chan []byte
	if len(udpMss) == 0 { // udp
		udpMss = append(udpMss, 1024)
		buf = make(chan []byte, 1) // avoid write too fast, udp drop direct
	} else {
		buf = make(chan []byte, 16)
	}

	var ctx, cancel = context.WithCancelCause(context.Background())
	defer cancel(nil)
	go func() {
		defer close(buf)
		for i := 0; i < size; {
			b := make([]byte, min(s.Int()%udpMss[0], size-i))
			s.Read(b)

			n, err := conn.Write(b)
			if err != nil {
				cancel(err)
				return
			}
			require.Equal(t, len(b), n)

			select {
			case buf <- b:
				i += len(b)
			case <-ctx.Done():
				return
			}
		}
	}()

	for i := 0; i < size; i++ {
		var exp []byte
		select {
		case <-ctx.Done():
			t.Errorf(ctx.Err().Error())
			t.FailNow()
		case exp = <-buf:
		}

		var b = make([]byte, len(exp))
		n, err := io.ReadFull(conn, b)
		require.NoError(t, err)
		require.Equal(t, len(exp), n)
		require.Equal(t, exp, b, n)

		i += n
	}
}

// todo: DuplexRawAndLink
func BindRawToUstack(t require.TestingT, ctx context.Context, us *ustack, raw sockit.RawConn) {
	var mtu = 1536
	go func() {
		var ip = packet.Make(0, mtu)
		sum := calcChecksum()
		for {
			ip.Sets(0, mtu)
			err := raw.Read(ctx, ip)
			if errors.Is(err, context.Canceled) {
				return
			}
			require.NoError(t, err)

			// recover tcp to ip packet
			ip.SetHead(0)
			sum(ip.Bytes()) // todo: TX?
			ValidIP(t, ip.Bytes())

			// iphdr := header.IPv4(ip.Data())
			// tcphdr := header.TCP(iphdr.Payload())
			// fmt.Printf(
			// 	"%s:%d-->%s:%d	%s\n",
			// 	iphdr.SourceAddress(), tcphdr.SourcePort(),
			// 	iphdr.DestinationAddress(), tcphdr.DestinationPort(),
			// 	tcphdr.Flags(),
			// )

			us.Inject(ip.Bytes())
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			ip := us.Read(ctx)
			if ip == nil {
				return
			}

			// iphdr := header.IPv4(ip)
			// tcphdr := header.TCP(iphdr.Payload())
			// fmt.Printf(
			// 	"%s:%d-->%s:%d	%s\n",
			// 	iphdr.SourceAddress(), tcphdr.SourcePort(),
			// 	iphdr.DestinationAddress(), tcphdr.DestinationPort(),
			// 	tcphdr.Flags(),
			// )

			err := raw.Write(ctx, packet.Make().Append(StripIP(ip)))
			require.NoError(t, err)
		}
	}()
}

func (u *ustack) Inject(ip []byte) {
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(ip)})
	u.link.InjectInbound(header.IPv4ProtocolNumber, pkb)
}

func (u *ustack) Read(ctx context.Context) (ip []byte) {
	pkb := u.link.ReadContext(ctx)
	if pkb.IsNil() {
		return nil // ctx cancel
	}
	defer pkb.DecRef()
	return pkb.ToView().AsSlice()
}

func (u *ustack) Addr() tcpip.Address {
	return u.addr
}

func (s *ustack) NetworkProtocolNumber() tcpip.TransportProtocolNumber {
	return header.ICMPv4ProtocolNumber
}

func (s *ustack) Stack() *stack.Stack { return s.stack }

func UDPCopy(t require.TestingT, conn net.Conn, mtu int) {
	var b = make([]byte, mtu)
	for {
		n, err := conn.Read(b[:cap(b)])
		if err != nil && errors.Is(err, net.ErrClosed) {
			return
		}
		require.NoError(t, err)

		m, err := conn.Write(b[:n])
		require.NoError(t, err)
		require.Equal(t, n, m)
	}
}
