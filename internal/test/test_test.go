package test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func Test_UsrStack_PingPong(t *testing.T) {
	const constNic tcpip.NICID = 123

	// todo:
	// addrs, err := createTuns(1)
	// require.NoError(t, err)
	var addrs []netip.Addr

	var constAddr = tcpip.AddrFromSlice(addrs[0].AsSlice())

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
