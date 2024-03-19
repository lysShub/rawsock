package tcp

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/lysShub/divert-go"
	"github.com/lysShub/rsocket"
	"github.com/lysShub/rsocket/test"
	"github.com/lysShub/rsocket/test/debug"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func init() {
	divert.MustLoad(divert.Mem)
}

func Test_Listen(t *testing.T) {
	t.Run("accept-once", func(t *testing.T) {
		addr := netip.AddrPortFrom(test.LocIP(), test.RandPort())

		var cnt atomic.Uint32
		go func() {
			l, err := Listen(addr)
			require.NoError(t, err)
			defer l.Close()

			for {
				conn, err := l.Accept()
				require.NoError(t, err)
				conn.Close()
				cnt.Add(1)
			}
		}()
		time.Sleep(time.Second)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			// system tcp dial will retransmit SYN packet
			_, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr.String())
			require.Error(t, err)
		}()

		time.Sleep(time.Second * 3)
		cancel()
		require.Equal(t, uint32(1), cnt.Load())
	})
}

func Test_Connect(t *testing.T) {
	t.Run("connect/loopback", func(t *testing.T) {
		// todo: maybe checksum offload?
		monkey.Patch(debug.Debug, func() bool { return false })

		var (
			saddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
			caddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
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
		us := test.NewUstack(t, caddr.Addr(), false)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		test.BindRawToUstack(t, ctx, us, raw)

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

	// t.Run("connect/not-loopback", func(t *testing.T) {
	// tp, err := test.CreateTunTuple()
	// require.NoError(t, err)
	// var (
	// 	saddr = netip.AddrPortFrom(tp.Addr1 /* 8080*/, test.RandPort())
	// 	caddr = netip.AddrPortFrom(tp.Addr2 /* 19986*/, test.RandPort())
	// )
	// defer tp.Close()
	// })

}

func Test_Complete_Check(t *testing.T) {
	// todo: maybe checksum offload?
	monkey.Patch(debug.Debug, func() bool { return false })

	t.Run("Read", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
			saddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
		)

		go func() {
			time.Sleep(time.Second)

			raw, err := Connect(saddr, caddr)
			require.NoError(t, err)
			defer raw.Close()

			tcp := test.BuildTCPSync(t, saddr, caddr)

			err = raw.WriteCtx(context.Background(), rsocket.ToPacket(0, tcp))
			require.NoError(t, err)
		}()

		raw, err := Connect(caddr, saddr)
		require.NoError(t, err)
		defer raw.Close()

		var ip = make([]byte, 39)
		n, err := raw.Read(ip)
		require.Zero(t, n)
		require.True(t, errors.Is(err, io.ErrShortBuffer))
	})

	t.Run("ReadCtx", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
			saddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
		)

		go func() {
			time.Sleep(time.Second)

			raw, err := Connect(saddr, caddr)
			require.NoError(t, err)
			defer raw.Close()

			tcp := test.BuildTCPSync(t, saddr, caddr)

			err = raw.WriteCtx(context.Background(), rsocket.ToPacket(0, tcp))
			require.NoError(t, err)
		}()

		raw, err := Connect(caddr, saddr)
		require.NoError(t, err)
		defer raw.Close()

		var p = rsocket.ToPacket(0, make([]byte, 39))
		err = raw.ReadCtx(context.Background(), p)
		require.True(t, errors.Is(err, io.ErrShortBuffer), err)
	})
}
