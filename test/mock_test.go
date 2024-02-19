package test

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Mock_RawConn(t *testing.T) {

	t.Run("MockRaw/PackLoss", func(t *testing.T) {
		var pl float32 = 0.01

		rawClient, rawServer := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP, RandPort()), netip.AddrPortFrom(LocIP, RandPort()),
			PacketLoss(pl),
		)
		defer rawClient.Close()
		defer rawServer.Close()

		var n int
		for i := 0; i < 1e4; i++ {
			if rawClient.loss() {
				n++
			}
		}

		exp := int(1e4 * pl)
		delta := 25

		require.Greater(t, n, exp-delta)
		require.Less(t, n, exp+delta)
	})

	t.Run("MockRaw/read-write", func(t *testing.T) {
		rawClient, rawServer := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP, RandPort()), netip.AddrPortFrom(LocIP, RandPort()),
		)
		defer rawClient.Close()
		defer rawServer.Close()

		_, err := rawClient.Write([]byte{1, 2})
		require.NoError(t, err)

		var b = make([]byte, 8)
		n, err := rawServer.Read(b)
		require.NoError(t, err)
		require.Equal(t, []byte{1, 2}, b[:n])

		_, err = rawServer.Write([]byte{3, 4})
		require.NoError(t, err)
	})

	t.Run("MockRaw/close", func(t *testing.T) {
		t.Skip("todo")
	})

	t.Run("MockRaw/ustack", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(LocIP, RandPort())
			caddr = netip.AddrPortFrom(LocIP, RandPort())
		)
		rawClient, rawServer := NewMockRaw(
			t, header.TCPProtocolNumber,
			caddr, saddr,
			ValidAddr, ValidChecksum, PacketLoss(0.05),
		)
		defer rawClient.Close()
		defer rawServer.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		// server
		go func() {
			us := NewUstack(t, saddr.Addr())
			BindRawToUstack(t, ctx, us, rawServer)

			l, err := gonet.ListenTCP(
				us.Stack(),
				tcpip.FullAddress{Addr: tcpip.AddrFrom4(saddr.Addr().As4()), Port: saddr.Port()},
				header.IPv4ProtocolNumber,
			)
			require.NoError(t, err)
			defer l.Close()

			conn, err := l.Accept()
			require.NoError(t, err)
			defer conn.Close()

			io.Copy(conn, conn)
		}()
		time.Sleep(time.Second)

		// client
		{
			us := NewUstack(t, caddr.Addr())
			BindRawToUstack(t, ctx, us, rawClient)

			conn, err := gonet.DialTCPWithBind(
				ctx, us.Stack(),
				tcpip.FullAddress{Addr: tcpip.AddrFrom4(caddr.Addr().As4()), Port: caddr.Port()},
				tcpip.FullAddress{Addr: tcpip.AddrFrom4(saddr.Addr().As4()), Port: saddr.Port()},
				header.IPv4ProtocolNumber,
			)
			require.NoError(t, err)
			defer conn.Close()

			msg := []byte("hellow world")
			_, err = conn.Write(msg)
			require.NoError(t, err)

			var b = make([]byte, 16)
			n, err := conn.Read(b)
			require.NoError(t, err)
			require.Equal(t, msg, b[:n])
		}

		cancel()
	})

}
