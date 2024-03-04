package test

import (
	"context"
	"io"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/relraw"
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
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
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
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
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

	t.Run("MockRaw/Write/memcpy", func(t *testing.T) {
		rawClient, rawServer := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
		)
		defer rawClient.Close()
		defer rawServer.Close()

		var tcphdr = []byte{0: 1, 1: 2, 19: 0}
		_, err := rawClient.Write(tcphdr)
		require.NoError(t, err)

		tcphdr[0] = 2

		var b = make([]byte, len(tcphdr))
		n, err := rawServer.Read(b)
		require.NoError(t, err)
		require.Equal(t, []byte{0: 1, 1: 2, 19: 0}, b[:n])
	})

	t.Run("MockRaw/WriteCtx/memcpy", func(t *testing.T) {
		rawClient, rawServer := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
		)
		defer rawClient.Close()
		defer rawServer.Close()

		p1 := relraw.NewPacket(20, 22)
		tcphdr := header.TCP(p1.Data())
		tcphdr.Encode(&header.TCPFields{DataOffset: 20})
		tcphdr.Payload()[0] = 1

		err := rawClient.WriteCtx(context.Background(), p1)
		require.NoError(t, err)

		p1.Data()[20] = 2

		p2 := relraw.NewPacket(0, 64)
		err = rawServer.ReadCtx(context.Background(), p2)
		require.NoError(t, err)
		require.Equal(t, byte(1), header.TCP(p2.Data()).Payload()[0])
	})

	t.Run("MockRaw/close", func(t *testing.T) {
		t.Skip("todo")
	})

	t.Run("MockRaw/ustack", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(LocIP(), RandPort())
			caddr = netip.AddrPortFrom(LocIP(), RandPort())

			seed int64 = time.Now().UnixNano()
			r          = rand.New(rand.NewSource(seed))
		)
		t.Log("seed", seed)
		rawClient, rawServer := NewMockRaw(
			t, header.TCPProtocolNumber,
			caddr, saddr,
			ValidAddr, ValidChecksum, PacketLoss(0.05),
		)
		defer rawClient.Close()
		defer rawServer.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		// server
		go func() {
			us := NewUstack(t, saddr.Addr(), false)
			BindRawToUstack(t, ctx, us, rawServer)

			l, err := gonet.ListenTCP(
				us.Stack(),
				tcpip.FullAddress{Addr: tcpip.AddrFrom4(saddr.Addr().As4()), Port: saddr.Port()},
				header.IPv4ProtocolNumber,
			)
			require.NoError(t, err)
			defer l.Close()

			tcp, err := l.Accept()
			require.NoError(t, err)
			defer tcp.Close()

			io.Copy(tcp, tcp)
		}()
		time.Sleep(time.Second)

		// client
		{
			us := NewUstack(t, caddr.Addr(), false)
			BindRawToUstack(t, ctx, us, rawClient)

			conn, err := gonet.DialTCPWithBind(
				ctx, us.Stack(),
				tcpip.FullAddress{Addr: tcpip.AddrFrom4(caddr.Addr().As4()), Port: caddr.Port()},
				tcpip.FullAddress{Addr: tcpip.AddrFrom4(saddr.Addr().As4()), Port: saddr.Port()},
				header.IPv4ProtocolNumber,
			)
			require.NoError(t, err)
			defer conn.Close()

			for i := 0; i < 64; i++ {
				var msg = make([]byte, r.Int31()%1023+1)
				r.Read(msg)

				_, err = conn.Write(msg)
				require.NoError(t, err)

				var b = make([]byte, len(msg))
				_, err = io.ReadFull(conn, b)
				require.NoError(t, err)

				require.Equal(t, string(msg), string(b), i)
			}
		}

		cancel()
	})

}
