package raw_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lysShub/raw"
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

func Test_RawConn_BPF_Filter(t *testing.T) {
	var (
		cPort = 1234
		sPort = 80
	)

	go func() {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: locIP, Port: sPort})
		require.NoError(t, err)
		defer l.Close()
		for {
			conn, err := l.AcceptTCP()
			require.NoError(t, err)
			// go io.Copy(conn, conn)

			go func() {
				defer conn.Close()
				var b = make([]byte, 1536)
				for {
					n, err := conn.Read(b)
					require.NoError(t, err)
					_, err = conn.Write(b[:n])
					require.NoError(t, err)
				}
			}()
		}
	}()

	raw, err := raw.NewRawTCP(&net.TCPAddr{IP: locIP, Port: cPort}, &net.TCPAddr{IP: locIP, Port: sPort})
	require.NoError(t, err)
	defer raw.Close()

	// noise
	go func() {
		conn, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: locIP})
		require.NoError(t, err)
		defer conn.Close()

		for {
			{
				b := []byte{
					0, 81, 4, 210, 250, 124, 53, 58, 0, 0, 0, 0, 160, 2, 114, 0, 180, 15, 0, 0, 2, 4, 5, 180, 1, 1, 8, 10, 112, 173, 219, 47, 0, 0, 0, 0, 1, 3, 3, 7,
				}
				_, err := conn.WriteToIP(b, &net.IPAddr{IP: locIP})
				require.NoError(t, err)
				time.Sleep(time.Millisecond * 10)
			}
			{
				b := []byte{
					0, 80, 4, 211, 250, 124, 53, 58, 0, 0, 0, 0, 160, 2, 114, 0, 180, 15, 0, 0, 2, 4, 5, 180, 1, 1, 8, 10, 112, 173, 219, 47, 0, 0, 0, 0, 1, 3, 3, 7,
				}
				_, err := conn.WriteToIP(b, &net.IPAddr{IP: locIP})
				require.NoError(t, err)
				time.Sleep(time.Millisecond * 10)
			}
			{
				b := []byte{
					0, 81, 4, 211, 250, 124, 53, 58, 0, 0, 0, 0, 160, 2, 114, 0, 180, 15, 0, 0, 2, 4, 5, 180, 1, 1, 8, 10, 112, 173, 219, 47, 0, 0, 0, 0, 1, 3, 3, 7,
				}
				_, err := conn.WriteToIP(b, &net.IPAddr{IP: locIP})
				require.NoError(t, err)
				time.Sleep(time.Millisecond * 10)
			}
		}
	}()

	//
	go func() {
		time.Sleep(time.Second)

		b := []byte{
			4, 210, 0, 80, 250, 124, 53, 58, 0, 0, 0, 0, 160, 2, 114, 0, 180, 15, 0, 0, 2, 4, 5, 180, 1, 1, 8, 10, 112, 173, 219, 47, 0, 0, 0, 0, 1, 3, 3, 7,
		}
		_, err = raw.Write(b)
		require.NoError(t, err)
	}()

	for i := 0; i < 2; i++ {
		var b = make([]byte, 1536)
		n, err := raw.Read(b)
		require.NoError(t, err)
		ipHdr := header.IPv4(b[:n])
		tcpHdr := header.TCP(ipHdr.Payload())

		require.Equal(t, uint16(80), tcpHdr.SourcePort())
		require.Equal(t, uint16(1234), tcpHdr.DestinationPort())
	}
}

func Test_RawConn_Dial_UsrStack_PingPong(t *testing.T) {
	var (
		cPort = 12345
		sPort = 8080
	)

	// server
	go func() {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: locIP, Port: sPort})
		require.NoError(t, err)
		defer l.Close()
		for {
			conn, err := l.AcceptTCP()
			require.NoError(t, err)
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	// usr-stack with raw-conn
	var conn net.Conn
	{
		raw, err := raw.NewRawTCP(&net.TCPAddr{IP: locIP, Port: cPort}, &net.TCPAddr{IP: locIP, Port: sPort})
		require.NoError(t, err)
		defer raw.Close()

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
				ipHdr = sum(ipHdr) // todo: why not right?

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

				n, err := raw.Write(ipHdr.Payload())
				require.True(
					t,
					err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF),
				)
				if n == 0 {
					break
				}
			}
		}()

		time.Sleep(time.Second) // ensure  uplink/downlink started
		conn, err = gonet.DialTCPWithBind(
			context.Background(),
			s,
			tcpip.FullAddress{
				NIC:  nicid,
				Addr: tcpip.AddrFromSlice(locIP),
				Port: uint16(cPort),
			},
			tcpip.FullAddress{
				NIC:  nicid,
				Addr: tcpip.AddrFromSlice(locIP),
				Port: uint16(sPort),
			},
			ipv4.ProtocolNumber,
		)
		require.Nil(t, err)
		defer conn.Close()
	}

	// client
	_, err := conn.Write([]byte("hello"))
	require.NoError(t, err)

	var b = make([]byte, 1536)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, []byte("hello"), b[:n])
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
