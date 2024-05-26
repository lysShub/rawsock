package test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/netkit/packet"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Mock_RawConn(t *testing.T) {

	t.Run("PackLoss", func(t *testing.T) {
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
				err := c.Write(packet.Make(20, 20))
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
		delta := int(float64(n) * 0.05)
		require.LessOrEqual(t, n-delta, exp)
		require.LessOrEqual(t, exp, n+delta)
	})

	t.Run("read-write", func(t *testing.T) {
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

		err := c.Write(packet.Make(20, 0, len(tcp)).Append(tcp))
		require.NoError(t, err)

		var b = packet.Make(0, 128)
		err = s.Read(b)
		require.NoError(t, err)
		require.Equal(t, []byte(tcp), b.Bytes())
	})

	t.Run("Write/memcpy1", func(t *testing.T) {
		c, s := NewMockRaw(
			t, header.TCPProtocolNumber,
			netip.AddrPortFrom(LocIP(), RandPort()), netip.AddrPortFrom(LocIP(), RandPort()),
		)
		defer c.Close()
		defer s.Close()

		var tcphdr = []byte{21: 1}
		err := c.Write(packet.Make(20, 0, len(tcphdr)).Append(tcphdr))
		require.NoError(t, err)

		tcphdr[21] = 2

		var b = packet.Make(0, len(tcphdr)+20)
		err = s.Read(b)
		require.NoError(t, err)
		require.Equal(t, uint8(1), b.Bytes()[21])
	})

	t.Run("Write/memcpy2", func(t *testing.T) {
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

		err := c.Write(packet.Make(20, 20))
		require.NoError(t, err)

		var p = packet.Make(0, 0, 64)
		start := time.Now()
		err = s.Read(p)
		require.NoError(t, err)
		require.Greater(t, time.Second*3, time.Since(start))
	})

	t.Run("stack", func(t *testing.T) {
		t.Skip("todo")
	})
}
