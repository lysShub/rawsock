package test

import (
	"context"
	"io"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/netkit/packet"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Mock_RawConn(t *testing.T) {

	t.Run("MockRaw/PackLoss", func(t *testing.T) {
		var pl float32 = 0.01

		c, s := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
			PacketLoss(pl),
		)
		defer c.Close()
		defer s.Close()

		go func() {
			for i := 0; i < 1e4; i++ {
				err := c.Write(packet.Make(0, 20))
				require.NoError(t, err)
			}
			c.Close()
			s.Close()
		}()

		var n int
		var p = packet.Make(0, 128)
		for {
			err := s.Read(p.SetHead(0))
			if err != nil {
				break
			}
			n++
		}

		exp := int(1e4 * (1 - pl))
		delta := 30
		require.LessOrEqual(t, n-delta, exp)
		require.LessOrEqual(t, exp, n+delta)
	})

	t.Run("MockRaw/read-write", func(t *testing.T) {
		c, s := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
		)
		defer c.Close()
		defer s.Close()
		tcp := BuildTCPSync(
			t,
			netip.AddrPortFrom(LocIP(), RandPort()),
			netip.AddrPortFrom(LocIP(), RandPort()),
		)

		err := c.Write(packet.Make().Append(tcp))
		require.NoError(t, err)

		var b = packet.Make(0, 128)
		err = s.Read(b)
		require.NoError(t, err)
		require.Equal(t, []byte(tcp), b.Bytes())
	})

	t.Run("MockRaw/Write/memcpy", func(t *testing.T) {
		c, s := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
		)
		defer c.Close()
		defer s.Close()

		var tcphdr = []byte{21: 1}
		err := c.Write(packet.Make().Append(tcphdr))
		require.NoError(t, err)

		tcphdr[21] = 2

		var b = packet.Make(0, len(tcphdr)+20)
		err = s.Read(b)
		require.NoError(t, err)
		require.Equal(t, uint8(1), b.Bytes()[21])
	})

	t.Run("MockRaw/WriteCtx/memcpy", func(t *testing.T) {
		c, s := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
		)
		defer c.Close()
		defer s.Close()

		p1 := packet.Make(20, 22)
		tcphdr := header.TCP(p1.Bytes())
		tcphdr.Encode(&header.TCPFields{DataOffset: 20})
		tcphdr.Payload()[0] = 1

		err := c.Write(p1)
		require.NoError(t, err)

		p1.Bytes()[20] = 2

		p2 := packet.Make(0, 64)
		err = s.Read(p2)
		require.NoError(t, err)
		require.Equal(t, byte(1), header.TCP(p2.Bytes()).Payload()[0])
	})

	t.Run("MockRaw/close", func(t *testing.T) {
		t.Skip("todo")
	})

	t.Run("MockRaw/delay", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(LocIP(), RandPort())
			caddr = netip.AddrPortFrom(LocIP(), RandPort())
		)
		c, s := NewMockRaw(
			t, header.TCPProtocolNumber,
			caddr, saddr,
			Delay(time.Second*2+time.Millisecond*500),
		)
		defer c.Close()
		defer s.Close()

		err := c.Write(packet.Make(0, 20))
		require.NoError(t, err)

		var p = packet.Make(0, 0, 64)
		start := time.Now()
		err = s.Read(p)
		require.NoError(t, err)
		require.Greater(t, time.Second*3, time.Since(start))
	})

	t.Run("MockRaw/ustack", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(LocIP(), RandPort())
			caddr = netip.AddrPortFrom(LocIP(), RandPort())

			seed int64 = time.Now().UnixNano()
			r          = rand.New(rand.NewSource(seed))
		)
		t.Log("seed", seed)
		c, s := NewMockRaw(
			t, header.TCPProtocolNumber,
			caddr, saddr,
			ValidAddr, ValidChecksum, PacketLoss(0.05),
		)
		defer c.Close()
		defer s.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		// server
		go func() {
			us := NewUstack(t, saddr.Addr(), false)
			BindRawToUstack(t, ctx, us, s)

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
			BindRawToUstack(t, ctx, us, c)

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
