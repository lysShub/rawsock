package bpf

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/internal/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_ListenLocal(t *testing.T) {

	t.Run("mutiple-use", func(t *testing.T) {
		addr := netip.AddrPortFrom(test.LocIP, test.RandPort())

		l1, addr1, err := listenLocal(addr, false)
		require.NoError(t, err)
		defer l1.Close()
		require.Equal(t, addr1, addr)

		l1, addr2, err := listenLocal(addr, false)
		require.Error(t, err)
		require.Nil(t, l1)
		require.False(t, addr2.IsValid())
	})

	t.Run("mutiple-use-not-used", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP, test.RandPort())

		l, _, err := listenLocal(addr, true)
		require.True(t, errors.Is(err, config.ErrNotUsedPort(addr.Port())))
		require.Nil(t, l)
	})

	t.Run("mutiple-use-after-used", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP, test.RandPort())

		l1, _, err := listenLocal(addr, false)
		require.NoError(t, err)
		defer l1.Close()

		l2, addr1, err := listenLocal(addr, true)
		require.NoError(t, err)
		require.Nil(t, l2)
		require.Equal(t, addr, addr1)
	})

	t.Run("auto-alloc-port", func(t *testing.T) {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0)

		l, addr2, err := listenLocal(addr, false)
		require.NoError(t, err)
		defer l.Close()
		require.Equal(t, addr2.Addr(), addr.Addr())
		require.NotZero(t, addr2.Port())
	})

	t.Run("auto-alloc-port2", func(t *testing.T) {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)

		l, addr2, err := listenLocal(addr, false)
		require.NoError(t, err)
		defer l.Close()
		require.Equal(t, addr2.Addr(), addr.Addr())
		require.NotZero(t, addr2.Port())
	})

	t.Run("avoid-send-SYN", func(t *testing.T) {
		addr := netip.AddrPortFrom(test.LocIP, test.RandPort())

		l, _, err := listenLocal(addr, false)
		require.NoError(t, err)
		defer l.Close()

		conn, err := net.DialTimeout("tcp", addr.String(), time.Second*2)
		require.True(t, errors.Is(err, context.DeadlineExceeded))
		require.Nil(t, conn)
	})

}

func Test_BPF_Filter(t *testing.T) {
	// todo: test conn tcp

	t.Run("TCPSynFilterBPF/loopback", func(t *testing.T) {
		t.Skip("todo")
	})

	t.Run("TCPSynFilterBPF/tuple-nic", func(t *testing.T) {
		tt, err := test.CreateTunTuple()
		require.NoError(t, err)
		var (
			saddr = netip.AddrPortFrom(tt.Addr1, test.RandPort())
			caddr = netip.AddrPortFrom(tt.Addr2, test.RandPort())
		)

		go func() {
			conn, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: caddr.Addr().AsSlice()})
			require.NoError(t, err)
			defer conn.Close()

			var noises = [][]byte{
				test.BuildRawTCP(t, caddr, saddr, make([]byte, 16)),

				// noise
				test.BuildRawTCP(t, saddr, caddr, make([]byte, 16)),
				test.BuildRawTCP(t, netip.AddrPortFrom(caddr.Addr(), test.RandPort()), saddr, make([]byte, 16)),
				test.BuildRawTCP(t, caddr, netip.AddrPortFrom(caddr.Addr(), test.RandPort()), make([]byte, 16)),
				test.BuildRawTCP(t,
					netip.AddrPortFrom(caddr.Addr(), test.RandPort()),
					netip.AddrPortFrom(saddr.Addr(), test.RandPort()),
					make([]byte, 16),
				),
			}

			for {
				for _, b := range noises {
					_, err := conn.WriteToIP(header.IPv4(b).Payload(), &net.IPAddr{IP: saddr.Addr().AsSlice()})
					require.NoError(t, err)
					time.Sleep(time.Millisecond * 100)
				}
			}
		}()

		raw, err := Connect(saddr, caddr)
		require.NoError(t, err)
		defer raw.Close()

		for i := 0; i < 3; i++ {
			var b = make([]byte, 1536)
			n, err := raw.Read(b)
			require.NoError(t, err)
			iphdr := header.IPv4(b[:n])

			tcpHdr := header.TCP(iphdr.Payload())
			require.Equal(t, caddr.Port(), tcpHdr.SourcePort())
			require.Equal(t, saddr.Port(), tcpHdr.DestinationPort())
		}
	})

}

func Test_Connect(t *testing.T) {

	t.Run("Connect/loopback", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
			saddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
		)

		go func() {
			l, err := net.ListenTCP("tcp", test.TCPAddr(saddr))
			require.NoError(t, err)
			defer l.Close()

			conn, err := l.AcceptTCP()
			require.NoError(t, err)

			_, err = io.Copy(conn, conn)
			require.NoError(t, err)
		}()
		time.Sleep(time.Second)

		raw, err := Connect(caddr, saddr)
		require.NoError(t, err)
		us := test.NewUstack(t, caddr.Addr())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		test.BindRaw(t, ctx, us, raw)

		conn, err := gonet.DialTCPWithBind(
			ctx, us.Stack(),
			test.FullAddress(caddr), test.FullAddress(saddr),
			header.IPv4ProtocolNumber,
		)
		require.NoError(t, err)

		req := []byte("hello world")
		_, err = conn.Write(req)
		require.NoError(t, err)

		resp := make([]byte, len(req))
		n, err := conn.Read(resp)
		require.NoError(t, err)
		require.Equal(t, req, resp[:n])

		require.NoError(t, conn.Close())
		cancel()
	})

	t.Run("Connnect/tuple-nic", func(t *testing.T) {
		t.Skip("todo")
	})
}

func Test_Recv(t *testing.T) {
	t.Run("RecvCtx/cancel", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
			saddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
		)

		const delay = time.Millisecond * 100
		conn, err := Connect(caddr, saddr, relraw.CtxCancelDelay(delay))
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(time.Second)
			cancel()
		}()

		p := relraw.ToPacket(0, make([]byte, 1536))
		s := time.Now()
		err = conn.ReadCtx(ctx, p)
		require.True(t, errors.Is(err, context.Canceled))
		require.Less(t, time.Since(s), time.Second+2*delay)
	})

}
