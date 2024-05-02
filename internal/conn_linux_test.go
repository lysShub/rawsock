//go:build linux
// +build linux

package rawsock_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	conni "github.com/lysShub/rawsock/internal"

	"github.com/lysShub/rawsock/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func Test_ListenLocal(t *testing.T) {
	t.Run("mutiple-use", func(t *testing.T) {
		addr := netip.AddrPortFrom(test.LocIP(), test.RandPort())

		l1, addr1, err := conni.ListenLocal(addr, false)
		require.NoError(t, err)
		defer l1.Close()
		require.Equal(t, addr1, addr)

		l1, addr2, err := conni.ListenLocal(addr, false)
		require.Error(t, err)
		require.Nil(t, l1)
		require.False(t, addr2.IsValid())
	})

	t.Run("mutiple-use-not-used", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP(), test.RandPort())

		l, _, err := conni.ListenLocal(addr, true)
		require.True(t, errors.Is(err, errors.WithStack(conni.ErrNotUsedPort(addr.Port()))))
		require.Nil(t, l)
	})

	t.Run("mutiple-use-after-used", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP(), test.RandPort())

		l1, _, err := conni.ListenLocal(addr, false)
		require.NoError(t, err)
		defer l1.Close()

		l2, addr1, err := conni.ListenLocal(addr, true)
		require.NoError(t, err)
		require.Nil(t, l2)
		require.Equal(t, addr, addr1)
	})

	t.Run("auto-alloc-port", func(t *testing.T) {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0)

		l, addr2, err := conni.ListenLocal(addr, false)
		require.NoError(t, err)
		defer l.Close()
		require.Equal(t, addr2.Addr(), addr.Addr())
		require.NotZero(t, addr2.Port())
	})

	t.Run("auto-alloc-port2", func(t *testing.T) {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)

		l, addr2, err := conni.ListenLocal(addr, false)
		require.NoError(t, err)
		defer l.Close()
		require.Equal(t, addr2.Addr(), addr.Addr())
		require.NotZero(t, addr2.Port())
	})

	t.Run("avoid-send-SYN", func(t *testing.T) {
		addr := netip.AddrPortFrom(test.LocIP(), test.RandPort())

		l, _, err := conni.ListenLocal(addr, false)
		require.NoError(t, err)
		defer l.Close()

		conn, err := net.DialTimeout("tcp", addr.String(), time.Second*2)
		require.True(t, errors.Is(err, context.DeadlineExceeded))
		require.Nil(t, conn)
	})

}

func Test_SetGRO(t *testing.T) {

	t.Run("base", func(t *testing.T) {
		err := conni.SetGRO(test.LocIP(), netip.AddrFrom4([4]byte{8, 8, 8, 8}), false)
		require.NoError(t, err)

		// todo: valid it

		// conni.SetGRO(test.LocIP(), netip.AddrFrom4([4]byte{8, 8, 8, 8}), true)
	})

}

func Test_SetGRO_Cache(t *testing.T) {
	t.Skip("todo")
}
