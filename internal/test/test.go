package test

import (
	"context"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync"
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
func PingPongWithUserStackClient(t *testing.T, clientAddr netip.Addr, raw relraw.RawConn) net.Conn {
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
		AddressWithPrefix: tcpip.AddrFromSlice(clientAddr.AsSlice()).WithPrefix(),
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

			// tcphdr := header.TCP(iphdr.Payload())
			// msg := fmt.Sprintf(
			// 	"%s:%d-->%s:%d",
			// 	iphdr.SourceAddress(), tcphdr.SourcePort(),
			// 	iphdr.DestinationAddress(), tcphdr.DestinationPort(),
			// )
			// fmt.Println(msg)

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(iphdr)})

			for !link.IsAttached() {
				time.Sleep(time.Millisecond * 10)
			}
			link.InjectInbound(ipv4.ProtocolNumber, pkt)
		}
	}()
	go func() { // uplink
		for {
			pkb := link.ReadContext(context.Background())

			s := pkb.ToView().AsSlice()
			require.Equal(t, 4, header.IPVersion(s))

			iphdr := header.IPv4(s)
			// iphdr = sum(iphdr)

			_, err := raw.Write(iphdr[iphdr.HeaderLength():])
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

func PingPongWithUserStackServer(t *testing.T, raw relraw.RawConn) net.Listener {
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

func BuildRawTCP(t *testing.T, laddr, raddr netip.AddrPort, payload []byte) header.IPv4 {
	s, err := relraw.NewIPStack(laddr.Addr(), raddr.Addr())
	require.NoError(t, err)

	iptcp := header.IPv4MinimumSize + header.TCPMinimumSize
	if laddr.Addr().Is6() {
		t.Fatal("only support IPv4")
	}
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

func RandPort() uint16 {
	p := uint16(rand.Uint32())
	if p < 1024 {
		p += 1536
	} else if p > 0xffff-64 {
		p -= 128
	}
	return p
}

var LocIP = func() netip.Addr {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}()

var tunTupleAddrsGener = func() func() []netip.Addr {
	var mu sync.RWMutex
	var addr = netip.AddrFrom4([4]byte{10, 3, 3, 0})

	return func() []netip.Addr {
		mu.Lock()
		defer mu.Unlock()

		var r = []netip.Addr{}
		for len(r) < 2 {
			addr = addr.Next()
			for tail := addr.As4()[3]; tail == 0 || tail == 0xff; {
				addr = addr.Next()
			}
			r = append(r, addr)
		}
		return r
	}
}()

func TCPAddr(a netip.AddrPort) *net.TCPAddr {
	return &net.TCPAddr{IP: a.Addr().AsSlice(), Port: int(a.Port())}
}

func UDPAddr(a netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{IP: a.Addr().AsSlice(), Port: int(a.Port())}
}
