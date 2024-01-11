package tcp

import (
	"context"
	"errors"
	"io"
	"net"
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

var locIP = func() net.IP {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	return (c.LocalAddr().(*net.UDPAddr)).IP
}()

func Test_UsrStack_PingPong(t *testing.T) {
	const constNic tcpip.NICID = 123
	var constAddr = tcpip.AddrFromSlice(locIP)

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
		AddressWithPrefix: tcpip.AddrFromSlice(locIP).WithPrefix(),
	}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicid}})

	go func() { // downlink
		sum := calcChecksum()
		for {
			var b = make([]byte, 1536)
			n, err := raw.Read(b)

			require.True(
				t,
				err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF),
				err,
			)
			if n == 0 {
				break
			}

			ipHdr := header.IPv4(b[:n])
			ipHdr = sum(ipHdr) // todo: maybe loopback?

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(ipHdr)})

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
			ipHdr := header.IPv4(s)
			ipHdr = sum(ipHdr)

			n, err := raw.Write(ipHdr)
			require.True(
				t,
				err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF),
			)
			if n == 0 {
				break
			}
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
			calcIP = ipHdr.IsChecksumValid()
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
