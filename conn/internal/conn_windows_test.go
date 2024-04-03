//go:build windows
// +build windows

package conn_test

import (
	"net/netip"
	"testing"

	conni "github.com/lysShub/sockit/conn/internal"
	"github.com/lysShub/sockit/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func Test_BindLocal(t *testing.T) {

	t.Run("UsedPort/normal", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP(), test.RandPort())

		fd1, _, err := conni.BindLocal(addr, false)
		require.NoError(t, err)
		defer windows.Close(fd1)

		fd2, addr1, err := conni.BindLocal(addr, true)
		require.NoError(t, err)
		require.Equal(t, windows.Handle(0), fd2)
		require.Equal(t, addr, addr1)
	})

	t.Run("UsedPort/repeat", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP(), test.RandPort())

		fd1, _, err := conni.BindLocal(addr, false)
		require.NoError(t, err)
		defer windows.Close(fd1)

		fd2, _, err := conni.BindLocal(addr, false)
		require.True(t, errors.Is(err, windows.WSAEADDRINUSE))
		require.Equal(t, windows.InvalidHandle, fd2)
	})

	t.Run("UsedPort/not-used", func(t *testing.T) {
		port := test.RandPort()
		var addr = netip.AddrPortFrom(test.LocIP(), port)

		fd1, _, err := conni.BindLocal(addr, true)
		require.True(t, errors.Is(err, conni.ErrNotUsedPort(port)))
		require.Equal(t, windows.InvalidHandle, fd1)
	})

}
