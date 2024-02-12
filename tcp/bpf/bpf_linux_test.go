package bpf

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/internal/config"
	"github.com/lysShub/relraw/internal/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Create_Tuns(t *testing.T) {
	tt, err := test.CreateTunTuple()
	require.NoError(t, err)

	var (
		saddr = netip.AddrPortFrom(tt.Addr1, test.RandPort())
		caddr = netip.AddrPortFrom(tt.Addr2, test.RandPort())
	)

	go func() {
		l, err := net.ListenTCP("tcp", test.TCPAddr(saddr))
		require.NoError(t, err)

		for {
			conn, err := l.AcceptTCP()
			require.NoError(t, err)
			go func() {
				io.Copy(conn, conn)
			}()
		}
	}()
	time.Sleep(time.Second)

	conn, err := net.DialTCP(
		"tcp",
		test.TCPAddr(caddr),
		test.TCPAddr(saddr),
	)
	require.NoError(t, err)

	_, err = conn.Write([]byte("hello world"))
	require.NoError(t, err)

	var b = make([]byte, 64)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, "hello world", string(b[:n]))
}

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
		require.True(t, errors.Is(err, config.ErrInvalidConfigUsedPort))
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
}

func Test_Recv_Ctx(t *testing.T) {
	var (
		caddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
		saddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
	)

	t.Run("cancel", func(t *testing.T) {
		const delay = time.Millisecond * 100
		conn, err := Connect(caddr, saddr, relraw.CtxCancelDelay(delay))
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(time.Second)
			cancel()
		}()

		var ip = make([]byte, 1536)
		s := time.Now()
		n, err := conn.ReadCtx(ctx, ip)
		require.True(t, errors.Is(err, os.ErrDeadlineExceeded))
		require.Zero(t, n)
		require.Less(t, time.Since(s), time.Second+2*delay)
	})
	// todo
}

func Test_RawConn_Dial_UsrStack_PingPong(t *testing.T) {
	tt, err := test.CreateTunTuple()
	require.NoError(t, err)

	var (
		cAddr = netip.AddrPortFrom(tt.Addr1, test.RandPort())
		sAddr = netip.AddrPortFrom(tt.Addr2, test.RandPort())
	)

	// server
	go func() {
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: sAddr.Addr().AsSlice(), Port: int(sAddr.Port())})
		require.NoError(t, err)
		defer l.Close()
		for {
			conn, err := l.AcceptTCP()
			require.NoError(t, err)
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	time.Sleep(time.Second)

	// usr-stack with raw-conn
	var conn net.Conn
	{
		raw, err := Connect(cAddr, sAddr)
		require.NoError(t, err)
		defer raw.Close()
		conn = test.PingPongWithUserStackClient(t, cAddr.Addr(), raw)
	}

	// client
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	var b = make([]byte, 1536)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, []byte("hello"), b[:n])
}
