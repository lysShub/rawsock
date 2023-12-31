package stack

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func Test_Gonet_Ping_Pong(t *testing.T) {
	var s *stack.Stack
	{
		s = stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			HandleLocal:        true,
		})

		if err := s.CreateNIC(constNic, channel.New(16, 1500, "")); err != nil {
			log.Fatal(err)
		}
		protocolAddr := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: constAddr.WithPrefix(),
		}
		if err := s.AddProtocolAddress(constNic, protocolAddr, stack.AddressProperties{}); err != nil {
			log.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", constNic, protocolAddr, err)
		}

		// Add default route.
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

		t.Log("accepting...")
		conn, err := l.Accept()
		require.NoError(t, err)
		go func(conn net.Conn) {
			var b = make([]byte, 1536)
			n, err := conn.Read(b)
			require.NoError(t, err)

			_, err = conn.Write(b[:n])
			require.NoError(t, err)
			err = conn.Close()
			require.NoError(t, err)
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

	b, err := io.ReadAll(conn)
	require.NoError(t, err)

	require.Equal(t, data, b)
}

func Test_Empty_Gonet_Ping_Pong(t *testing.T) {
	var s *stack.Stack
	{
		s = stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ /*NewIPv4*/ },
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			HandleLocal:        true,
		})

		if err := s.CreateNIC(constNic, NewLink(1500)); err != nil {
			log.Fatal(err)
		}
		protocolAddr := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: constAddr.WithPrefix(),
		}
		if err := s.AddProtocolAddress(constNic, protocolAddr, stack.AddressProperties{}); err != nil {
			log.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", constNic, protocolAddr, err)
		}

		// Add default route.
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

		t.Log("accepting...")
		conn, err := l.Accept()
		require.NoError(t, err)
		go func(conn net.Conn) {
			var b = make([]byte, 1536)
			n, err := conn.Read(b)
			require.NoError(t, err)

			_, err = conn.Write(b[:n])
			require.NoError(t, err)
			err = conn.Close()
			require.NoError(t, err)
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

	b, err := io.ReadAll(conn)
	require.NoError(t, err)

	require.Equal(t, data, b)
}

func Test_NewTCPStackGvisor_Ping_Pong(t *testing.T) {

	a, err := NewTCPStackGvisor(124, 80, 1500)
	require.NoError(t, err)
	b, err := NewTCPStackGvisor(80, 124, 1500)
	require.NoError(t, err)

	// raw
	go func() {
		for {
			h, err := a.RecvRaw()
			require.NoError(t, err)

			// src, dst := h.SourcePort(), h.DestinationPort()
			// h.SetDestinationPort(src)

			_, err = b.SendRaw(h)
			require.NoError(t, err)
		}
	}()

	// ping-pong
	go func() {
		var data = make([]byte, 1536)
		n, err := b.RecvSeg(data)
		require.NoError(t, err)

		_, err = b.SendSeg(data[:n])
		require.NoError(t, err)
	}()

	n, err := a.SendSeg([]byte("hello"))
	t.Log(n, err)

}
