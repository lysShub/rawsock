package raw

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/pkg/errors"

	"github.com/lysShub/sockit/conn"
	"github.com/lysShub/sockit/packet"
	"github.com/lysShub/sockit/test"
	"github.com/lysShub/sockit/test/debug"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Raw_Listen(t *testing.T) {
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
	t.Run("loopback", func(t *testing.T) {
		// todo: maybe checksum offload?
		monkey.Patch(debug.Debug, func() bool { return false })

		var (
			caddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
			saddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
			seed  = time.Now().UnixNano()
			r     = rand.New(rand.NewSource(seed))
		)
		t.Log("seed: ", seed)

		retCh := make(chan struct{})
		go func() {
			// todo: add noise
			l, err := net.ListenTCP("tcp", test.TCPAddr(saddr))
			require.NoError(t, err)
			defer l.Close()

			conn, err := l.AcceptTCP()
			require.NoError(t, err)

			_, err = io.Copy(conn, conn)
			require.NoError(t, err)
			close(retCh)
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
		defer conn.Close()

		test.ValidPingPongConn(t, r, conn, 0xffff)
		require.NoError(t, conn.Close())
		cancel()

		<-retCh
	})

	t.Run("nics", func(t *testing.T) {
		// todo: maybe checksum offload?
		monkey.Patch(debug.Debug, func() bool { return false })

		tt := test.CreateTunTuple(t)
		defer tt.Close()
		var (
			saddr = netip.AddrPortFrom(tt.Addr1, test.RandPort())
			caddr = netip.AddrPortFrom(tt.Addr2, test.RandPort())
			seed  = time.Now().UnixNano()
			r     = rand.New(rand.NewSource(seed))
		)
		t.Log("seed: ", seed)

		retCh := make(chan struct{})
		go func() {
			// todo: add noise
			l, err := net.ListenTCP("tcp", test.TCPAddr(saddr))
			require.NoError(t, err)
			defer l.Close()

			conn, err := l.AcceptTCP()
			require.NoError(t, err)

			_, err = io.Copy(conn, conn)
			require.NoError(t, err)
			close(retCh)
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
		defer conn.Close()

		test.ValidPingPongConn(t, r, conn, 0xffff)
		require.NoError(t, conn.Close())
		cancel()

		<-retCh
	})
}

func Test_Context(t *testing.T) {
	var (
		caddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
		saddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
	)

	const period = time.Millisecond * 100
	tcp, err := Connect(caddr, saddr, conn.CtxPeriod(period))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(time.Second)
		cancel()
	}()

	p := packet.Make(0, 1356)
	s := time.Now()
	err = tcp.Read(ctx, p)
	require.True(t, errors.Is(err, context.Canceled))
	require.Less(t, time.Since(s), time.Second+2*period)
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

			err = raw.Write(context.Background(), packet.Make().Append(tcp))
			require.NoError(t, err)
		}()

		raw, err := Connect(caddr, saddr)
		require.NoError(t, err)
		defer raw.Close()

		var ip = packet.Make(0, 39)
		err = raw.Read(context.Background(), ip)
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

			err = raw.Write(context.Background(), packet.Make().Append(tcp))
			require.NoError(t, err)
		}()

		raw, err := Connect(caddr, saddr)
		require.NoError(t, err)
		defer raw.Close()

		var p = packet.Make(0, 39)
		err = raw.Read(context.Background(), p)
		require.True(t, errors.Is(err, io.ErrShortBuffer))
	})
}
