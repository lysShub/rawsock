package test

import (
	"context"
	"io"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/sockit/packet"
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
		delta := 30

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
		tcp := BuildTCPSync(
			t,
			netip.AddrPortFrom(LocIP(), RandPort()),
			netip.AddrPortFrom(LocIP(), RandPort()),
		)

		err := rawClient.Write(context.Background(), packet.ToPacket(0, tcp))
		require.NoError(t, err)

		var b = packet.ToPacket(0, make([]byte, 128))
		err = rawServer.Read(context.Background(), b)
		require.NoError(t, err)
		require.Equal(t, []byte(tcp), b.Data())
	})

	t.Run("MockRaw/Write/memcpy", func(t *testing.T) {
		rawClient, rawServer := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
		)
		defer rawClient.Close()
		defer rawServer.Close()

		var tcphdr = []byte{21: 1}
		err := rawClient.Write(context.Background(), packet.ToPacket(0, tcphdr))
		require.NoError(t, err)

		tcphdr[21] = 2

		var b = packet.ToPacket(0, make([]byte, len(tcphdr)+20))
		err = rawServer.Read(context.Background(), b)
		require.NoError(t, err)
		require.Equal(t, uint8(1), b.Data()[21])
	})

	t.Run("MockRaw/WriteCtx/memcpy", func(t *testing.T) {
		rawClient, rawServer := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
		)
		defer rawClient.Close()
		defer rawServer.Close()

		p1 := packet.NewPacket(20, 22)
		tcphdr := header.TCP(p1.Data())
		tcphdr.Encode(&header.TCPFields{DataOffset: 20})
		tcphdr.Payload()[0] = 1

		err := rawClient.Write(context.Background(), p1)
		require.NoError(t, err)

		p1.Data()[20] = 2

		p2 := packet.NewPacket(0, 64)
		err = rawServer.Read(context.Background(), p2)
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
