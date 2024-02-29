package internal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/test"
	"github.com/stretchr/testify/require"
)

func Test_ListenLocal(t *testing.T) {
	t.Run("mutiple-use", func(t *testing.T) {
		addr := netip.AddrPortFrom(test.LocIP, test.RandPort())

		l1, addr1, err := ListenLocal(addr, false)
		require.NoError(t, err)
		defer l1.Close()
		require.Equal(t, addr1, addr)

		l1, addr2, err := ListenLocal(addr, false)
		require.Error(t, err)
		require.Nil(t, l1)
		require.False(t, addr2.IsValid())
	})

	t.Run("mutiple-use-not-used", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP, test.RandPort())

		l, _, err := ListenLocal(addr, true)
		require.True(t, errors.Is(err, config.ErrNotUsedPort(addr.Port())))
		require.Nil(t, l)
	})

	t.Run("mutiple-use-after-used", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP, test.RandPort())

		l1, _, err := ListenLocal(addr, false)
		require.NoError(t, err)
		defer l1.Close()

		l2, addr1, err := ListenLocal(addr, true)
		require.NoError(t, err)
		require.Nil(t, l2)
		require.Equal(t, addr, addr1)
	})

	t.Run("auto-alloc-port", func(t *testing.T) {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0)

		l, addr2, err := ListenLocal(addr, false)
		require.NoError(t, err)
		defer l.Close()
		require.Equal(t, addr2.Addr(), addr.Addr())
		require.NotZero(t, addr2.Port())
	})

	t.Run("auto-alloc-port2", func(t *testing.T) {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 0)

		l, addr2, err := ListenLocal(addr, false)
		require.NoError(t, err)
		defer l.Close()
		require.Equal(t, addr2.Addr(), addr.Addr())
		require.NotZero(t, addr2.Port())
	})

	t.Run("avoid-send-SYN", func(t *testing.T) {
		addr := netip.AddrPortFrom(test.LocIP, test.RandPort())

		l, _, err := ListenLocal(addr, false)
		require.NoError(t, err)
		defer l.Close()

		conn, err := net.DialTimeout("tcp", addr.String(), time.Second*2)
		require.True(t, errors.Is(err, context.DeadlineExceeded))
		require.Nil(t, conn)
	})

}
