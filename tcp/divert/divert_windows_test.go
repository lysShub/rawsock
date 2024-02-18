package divert

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/divert-go"
	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/internal/test"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func init() {
	divert.MustLoad(divert.DLL, divert.Sys)
}

func Test_Bind_Local(t *testing.T) {

	t.Run("UsedPort/normal", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP, test.RandPort())

		fd1, _, err := bindLocal(addr, false)
		require.NoError(t, err)
		defer windows.Close(fd1)

		fd2, addr1, err := bindLocal(addr, true)
		require.NoError(t, err)
		require.Equal(t, windows.Handle(0), fd2)
		require.Equal(t, addr, addr1)
	})

	t.Run("UsedPort/repeat", func(t *testing.T) {
		var addr = netip.AddrPortFrom(test.LocIP, test.RandPort())

		fd1, _, err := bindLocal(addr, false)
		require.NoError(t, err)
		defer windows.Close(fd1)

		fd2, _, err := bindLocal(addr, false)
		require.True(t, errors.Is(err, windows.WSAEADDRINUSE))
		require.Equal(t, windows.InvalidHandle, fd2)
	})

	t.Run("UsedPort/not-used", func(t *testing.T) {
		port := test.RandPort()
		var addr = netip.AddrPortFrom(test.LocIP, port)

		fd1, _, err := bindLocal(addr, true)
		require.True(t, errors.Is(err, config.ErrNotUsedPort(port)))
		require.Equal(t, windows.InvalidHandle, fd1)
	})

}

func Test_Connect(t *testing.T) {

	t.Run("connect/loopback", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(test.LocIP /* 8080*/, test.RandPort())
			caddr = netip.AddrPortFrom(test.LocIP /* 19986*/, test.RandPort())
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

func Test_Listen(t *testing.T) {
	t.Skip("")
}
