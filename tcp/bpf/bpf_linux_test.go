package bpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lysShub/relraw"
	"github.com/lysShub/relraw/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Listen(t *testing.T) {

	t.Run("accept-once", func(t *testing.T) {
		addr := netip.AddrPortFrom(test.LocIP, test.RandPort())

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

		go func() {
			conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: test.LocIP.AsSlice(), Port: int(addr.Port())})
			fmt.Println(conn, err)
		}()

		time.Sleep(time.Second * 2)
		require.Equal(t, uint32(1), cnt.Load())
	})

}

func Test_Connect(t *testing.T) {

	t.Run("loopback", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
			saddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
		)

		// todo: add noise
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

	t.Run("nics", func(t *testing.T) {
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

func Test_Recv(t *testing.T) {
	t.Run("RecvCtx/cancel", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
			saddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
		)

		const delay = time.Millisecond * 100
		conn, err := Connect(caddr, saddr, relraw.CtxDelay(delay))
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
