package tcp

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/relraw"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

var locIP = func() netip.Addr {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}()

func Test_UsrStack_PingPong(t *testing.T) {
	const constNic tcpip.NICID = 123
	var constAddr = tcpip.AddrFromSlice(locIP.AsSlice())

	var s *stack.Stack
	{
		s = stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			// HandleLocal:        true,
		})

		link := channel.New(16, 1500, "")
		go func() {
			for !link.IsAttached() {
				time.Sleep(time.Millisecond * 50)
			}
			for {
				pkb := link.ReadContext(context.Background())

				link.InjectInbound(
					ipv4.ProtocolNumber,
					stack.NewPacketBuffer(stack.PacketBufferOptions{
						Payload: buffer.MakeWithView(pkb.ToView()),
					}),
				)
			}
		}()

		err := s.CreateNIC(constNic, link)
		require.Nil(t, err)
		err = s.AddProtocolAddress(
			constNic,
			tcpip.ProtocolAddress{
				Protocol:          ipv4.ProtocolNumber,
				AddressWithPrefix: constAddr.WithPrefix(),
			},
			stack.AddressProperties{},
		)
		require.Nil(t, err)
		s.SetRouteTable([]tcpip.Route{{
			Destination: header.IPv4EmptySubnet,
			NIC:         constNic,
		}})
	}

	go func() {
		l, err := gonet.ListenTCP(s, tcpip.FullAddress{
			NIC:  constNic,
			Addr: constAddr,
			Port: 80,
		}, header.IPv4ProtocolNumber)
		require.NoError(t, err)

		conn, err := l.Accept()
		require.NoError(t, err)
		go func(conn net.Conn) {
			io.Copy(conn, conn)
		}(conn)
	}()
	time.Sleep(time.Second)

	conn, err := gonet.DialTCP(s, tcpip.FullAddress{
		NIC:  constNic,
		Addr: constAddr,
		Port: 80,
	}, ipv4.ProtocolNumber)
	require.NoError(t, err)

	data := []byte("123")

	_, err = conn.Write(data)
	require.NoError(t, err)

	n, err := conn.Read(data)
	require.NoError(t, err)
	require.Equal(t, data[:n], []byte("123"))
}

/*
*  ┌────────────────────┐                       │
*  │    gvistor.Stack   │                       │             ┌───────────────────┐
*  │   ┌────────────┐   │      ┌─────────┐      │             │                   │
*  │   │            ├───┼─────>│         ├──────┼────────────>┤   net.Listener    │
*  │   │ link layer │   │      │  RawTCP │      │             │                   │
*  │   │            │<──┼──────┤         ├<─────┼─────────────┤                   │
*  │   ├────────────┤   │      └─────────┘      │             │   pong-server     │
*  │   │            │<──┼────"hello world"      │             │                   │
*  │   │   gonet    │   │                       │             └───────────────────┘
*  │   │            ├───┼───>"hello world"      │
*  └───┴────────────┴───┘                       │
 */
func pingPongWithUserStackClient(t *testing.T, raw relraw.Raw) net.Conn {
	const nicid tcpip.NICID = 11

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		// HandleLocal:        true,
	})
	link := channel.New(4, uint32(1500), "")
	if err := s.CreateNIC(nicid, link); err != nil {
		require.Nil(t, err)
	}
	s.AddProtocolAddress(nicid, tcpip.ProtocolAddress{
		Protocol:          header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(locIP.AsSlice()).WithPrefix(),
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicid}})

	go func() { // downlink
		sum := calcChecksum()
		for {
			var b = make([]byte, 1536)
			n, err := raw.Read(b)

			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				print()
			}
			require.NoError(t, err)

			iphdr := header.IPv4(b[:n])
			iphdr = sum(iphdr) // todo: maybe loopback?

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(iphdr)})

			for !link.IsAttached() {
				time.Sleep(time.Millisecond * 10)
			}
			link.InjectInbound(ipv4.ProtocolNumber, pkt)
		}
	}()
	go func() { // uplink
		sum := calcChecksum()
		for {
			pkb := link.ReadContext(context.Background())

			s := pkb.ToView().AsSlice()
			iphdr := header.IPv4(s)
			iphdr = sum(iphdr)

			_, err := raw.Write(iphdr)
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
		}
	}()

	caddr, saddr := raw.LocalAddr().(*net.TCPAddr), raw.RemoteAddr().(*net.TCPAddr)
	conn, err := gonet.DialTCPWithBind(
		context.Background(),
		s,
		tcpip.FullAddress{
			NIC:  nicid,
			Addr: tcpip.AddrFromSlice(caddr.IP),
			Port: uint16(caddr.Port),
		},
		tcpip.FullAddress{
			NIC:  nicid,
			Addr: tcpip.AddrFromSlice(saddr.IP),
			Port: uint16(saddr.Port),
		},
		ipv4.ProtocolNumber,
	)
	require.Nil(t, err)

	return conn
}

func pingPongWithUserStackServer(t *testing.T, raw relraw.Raw) net.Listener {
	return nil
}

func calcChecksum() func(ipHdr header.IPv4) header.IPv4 {
	var (
		first   = true
		calcIP  = false
		calcTCP = true
	)
	return func(ipHdr header.IPv4) header.IPv4 {
		tcpHdr := header.TCP(ipHdr.Payload())
		if first {
			calcIP = !ipHdr.IsChecksumValid()
			calcTCP = !tcpHdr.IsChecksumValid(
				ipHdr.SourceAddress(),
				ipHdr.DestinationAddress(),
				checksum.Checksum(tcpHdr.Payload(), 0),
				uint16(len(tcpHdr.Payload())),
			)
			first = false
		}

		if calcIP {
			ipHdr.SetChecksum(0)
			s := checksum.Checksum(ipHdr[:ipHdr.HeaderLength()], 0)
			ipHdr.SetChecksum(^s)
		}

		if calcTCP {

			s := header.PseudoHeaderChecksum(
				tcp.ProtocolNumber,
				ipHdr.SourceAddress(),
				ipHdr.DestinationAddress(),
				uint16(len(tcpHdr)),
			)
			s = checksum.Checksum(tcpHdr.Payload(), s)
			tcpHdr.SetChecksum(0)
			s = tcpHdr.CalculateChecksum(s)
			tcpHdr.SetChecksum(^s)
		}
		return ipHdr
	}
}

func buildRawTCP(t *testing.T, laddr, raddr netip.AddrPort, totalSize int) header.IPv4 {
	s, err := relraw.NewIPStack(laddr.Addr(), raddr.Addr())
	require.NoError(t, err)

	var b = make([]byte, totalSize)
	rand.Read(b[header.IPv4MinimumSize+header.TCPMinimumSize:])

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

	psoSum := s.AttachHeader(b, header.TCPProtocolNumber)

	tcphdr.SetChecksum(^checksum.Checksum(tcphdr, psoSum))

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

func randPort() uint16 {
	b, err := rand.Int(rand.Reader, big.NewInt(0xff))
	if err != nil {
		panic(err)
	}

	p := uint16(b.Int64())
	if p < 1024 {
		p += 1536
	} else if p > 0xffff-64 {
		p -= 128
	}
	return p
}
