//go:build linux
// +build linux

package raw

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/lysShub/netkit/debug"
	"github.com/lysShub/netkit/packet"
	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Connect(t *testing.T) {
	monkey.Patch(debug.Debug, func() bool { return false })

	t.Run("base", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
			saddr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
		)

		go func() {
			conn, err := net.DialUDP("udp", test.UDPAddr(caddr), test.UDPAddr(saddr))
			require.NoError(t, err)
			defer conn.Close()

			time.Sleep(time.Second * 2)
			conn.Write([]byte("hello"))
		}()

		raw, err := Connect(saddr, caddr)
		require.NoError(t, err)
		defer raw.Close()
		var p = packet.Make(0, 1536)
		err = raw.Read(p)
		require.NoError(t, err)

		u := header.UDP(p.Bytes())
		require.Equal(t, caddr.Port(), u.SourcePort())
		require.Equal(t, saddr.Port(), u.DestinationPort())
	})

	t.Run("loopback", func(t *testing.T) {
		t.Skip("data changed or out-of-order")

		// todo: maybe checksum offload?
		monkey.Patch(debug.Debug, func() bool { return false })

		var (
			caddr = netip.AddrPortFrom(test.LocIP() /* test.RandPort() */, 19986)
			saddr = netip.AddrPortFrom(test.LocIP() /* test.RandPort() */, 8080)
			seed  = time.Now().UnixNano()
			r     = rand.New(rand.NewSource(seed))
			mtu   = 1460
		)
		t.Log("seed: ", seed)

		eg, ctx := errgroup.WithContext(context.Background())

		eg.Go(func() error {
			// todo: add noise
			conn, err := net.DialUDP("udp", test.UDPAddr(saddr), test.UDPAddr(caddr))
			require.NoError(t, err)
			defer conn.Close()

			test.UDPCopy(t, conn, mtu)
			return nil
		})
		time.Sleep(time.Second)
		raw, err := Connect(caddr, saddr)
		require.NoError(t, err)
		us := test.NewUstack(t, caddr.Addr(), false)

		test.BindRawToUstack(t, ctx, us, raw)

		conn, err := gonet.DialUDP(
			us.Stack(),
			test.FullAddressPtr(caddr), test.FullAddressPtr(saddr),
			header.IPv4ProtocolNumber,
		)
		require.NoError(t, err)
		defer conn.Close()

		test.ValidPingPongConn(t, r, conn, 0xffff, 1460)
		require.NoError(t, conn.Close())

		err = eg.Wait()
		ok := errors.Is(err, unix.ECONNRESET) || // todo: why gvisor send RST?
			errors.Is(err, io.EOF)
		require.True(t, ok)
	})
}

func Test_Default_Addr(t *testing.T) {
	var addr = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)

	t.Run("dial", func(t *testing.T) {
		conn, err := Connect(addr, netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), 56))
		require.NoError(t, err)
		defer conn.Close()

		laddr := conn.LocalAddr()
		require.Equal(t, test.LocIP(), laddr.Addr())
		require.NotZero(t, laddr.Port())
	})
}
