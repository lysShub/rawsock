package raw

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/lysShub/sockit/conn"
	"github.com/lysShub/sockit/packet"
	"github.com/lysShub/sockit/test"
	"github.com/lysShub/sockit/test/debug"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Raw_Listen(t *testing.T) {
	t.Run("loopback", func(t *testing.T) {
		// todo: if loopback, should set tso/gso:
		//   ethtool -K lo tcp-segmentation-offload off
		//   ethtool -K lo generic-segmentation-offload off

		var (
			saddr  = netip.AddrPortFrom(test.LocIP(), test.RandPort())
			caddrs = []netip.AddrPort{
				netip.AddrPortFrom(test.LocIP(), test.RandPort()),
				netip.AddrPortFrom(test.LocIP(), test.RandPort()),
				netip.AddrPortFrom(test.LocIP(), test.RandPort()),
			}
			cnt atomic.Uint32
		)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		eg, ctx := errgroup.WithContext(ctx)

		for _, caddr := range caddrs {
			addr := caddr
			eg.Go(func() error {
				time.Sleep(time.Second)

				_, err := net.DialTCP("tcp", test.TCPAddr(addr), test.TCPAddr(saddr))
				require.True(t, errors.Is(err, unix.ECONNREFUSED))
				return nil
			})
		}

		eg.Go(func() error {
			l, err := Listen(saddr)
			require.NoError(t, err)
			defer l.Close()
			context.AfterFunc(ctx, func() { l.Close() })

			for cnt.Load() < 3 {
				conn, err := l.Accept()
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				require.NoError(t, err)
				conn.Close() // todo: accept it

				require.True(t, slices.Contains(caddrs, conn.RemoteAddr()))
				cnt.Add(1)
			}
			return nil
		})

		time.Sleep(time.Second)
		err := eg.Wait()
		require.NoError(t, err)
	})
}

func Test_AcceptOnce(t *testing.T) {
	// only accept once for multiple packets with the same ISN in a period of time
	var (
		addr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
		cnt  atomic.Uint32
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eg, ctx := errgroup.WithContext(ctx)

	// system tcp dial will retransmit SYN packet
	eg.Go(func() error {
		time.Sleep(time.Second)
		_, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr.String())
		require.Error(t, err)
		return nil
	})
	eg.Go(func() error {
		time.Sleep(time.Second)
		_, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr.String())
		require.Error(t, err)
		return nil
	})

	eg.Go(func() error {
		l, err := Listen(addr)
		require.NoError(t, err)
		defer l.Close()
		context.AfterFunc(ctx, func() { l.Close() })

		for {
			conn, err := l.Accept()
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			require.NoError(t, err)
			conn.Close()
			cnt.Add(1)
		}
	})

	time.Sleep(time.Second * 4)
	cancel()
	eg.Wait()

	require.Equal(t, uint32(2), cnt.Load())
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

		eg, ctx := errgroup.WithContext(context.Background())

		eg.Go(func() error {
			// todo: add noise
			l, err := net.ListenTCP("tcp", test.TCPAddr(saddr))
			require.NoError(t, err)
			defer l.Close()

			conn, err := l.AcceptTCP()
			require.NoError(t, err)

			_, err = io.Copy(conn, conn)
			return err
		})
		time.Sleep(time.Second)

		raw, err := Connect(caddr, saddr)
		require.NoError(t, err)
		us := test.NewUstack(t, caddr.Addr(), false)

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

		err = eg.Wait()
		ok := errors.Is(err, unix.ECONNRESET) || // todo: why gvisor send RST?
			errors.Is(err, io.EOF) || err == nil
		require.True(t, ok)
	})

	t.Run("nics", func(t *testing.T) {
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

		eg, ctx := errgroup.WithContext(context.Background())

		eg.Go(func() error {
			// todo: add noise
			l, err := net.ListenTCP("tcp", test.TCPAddr(saddr))
			require.NoError(t, err)
			defer l.Close()

			conn, err := l.AcceptTCP()
			require.NoError(t, err)

			_, err = io.Copy(conn, conn)
			return err
		})
		time.Sleep(time.Second)

		raw, err := Connect(caddr, saddr)
		require.NoError(t, err)
		us := test.NewUstack(t, caddr.Addr(), false)
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

		err = eg.Wait()
		ok := errors.Is(err, unix.ECONNRESET) ||
			errors.Is(err, io.EOF) || err == nil
		require.True(t, ok)
	})
}

func Test_Default_Addr(t *testing.T) {
	var addr = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	t.Run("listen", func(t *testing.T) {
		l, err := Listen(addr)
		require.NoError(t, err)
		defer l.Close()

		laddr := l.Addr()
		require.Equal(t, test.LocIP(), laddr.Addr())
		require.NotZero(t, laddr.Port())
	})

	t.Run("dial", func(t *testing.T) {
		conn, err := Connect(addr, netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 80))
		require.NoError(t, err)
		defer conn.Close()

		laddr := conn.LocalAddr()
		require.Equal(t, test.LocIP(), laddr.Addr())
		require.NotZero(t, laddr.Port())
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

		var ip = packet.Make(0, 39, 0)
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

		var p = packet.Make(0, 39, 0)
		err = raw.Read(context.Background(), p)
		require.True(t, errors.Is(err, io.ErrShortBuffer))
	})
}
