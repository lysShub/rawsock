package tcp

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lysShub/rsocket/test"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Listen(t *testing.T) {

	t.Run("accept-once", func(t *testing.T) {
		// test listenter only accept once, with repeat SYN pacekt(same SEQ)
		var (
			addr = netip.AddrPortFrom(test.LocIP(), test.RandPort())
			cnt  atomic.Uint32
		)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		gs, ctx := errgroup.WithContext(ctx)

		gs.Go(func() error {
			l, err := ListenEth(addr)
			require.NoError(t, err)
			defer l.Close()
			context.AfterFunc(ctx, func() {
				l.Close()
			})

			for {
				conn, err := l.Accept()
				select {
				case <-ctx.Done():
					return nil
				default:
				}

				require.NoError(t, err)
				conn.Close()
				cnt.Add(1)
			}
		})
		time.Sleep(time.Second)

		// system tcp dial will retransmit SYN packet
		gs.Go(func() error {
			_, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr.String())
			require.Error(t, err)
			return nil
		})

		time.Sleep(time.Second * 5)
		cancel()
		gs.Wait()
		require.Equal(t, uint32(1), cnt.Load())
	})
}

func Test(t *testing.T) {
	var (
		caddr = netip.AddrPortFrom(test.LocIP() /* test.RandPort() */, 19986)
		saddr = netip.AddrPortFrom(test.LocIP() /* test.RandPort() */, 8080)
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

	conn, err := net.DialTCP("tcp", test.TCPAddr(caddr), test.TCPAddr(saddr))
	require.NoError(t, err)
	defer conn.Close()

	msg := "hello"
	_, err = conn.Write([]byte(msg))
	require.NoError(t, err)
}

func Test_Conn(t *testing.T) {
	// test connect with system tcp stack echo server

	var (
		caddr = netip.AddrPortFrom(test.LocIP() /* test.RandPort() */, 19986)
		saddr = netip.AddrPortFrom(test.LocIP() /* test.RandPort() */, 8080)
		seed  = time.Now().UnixNano()
		r     = rand.New(rand.NewSource(seed))
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gs, ctx := errgroup.WithContext(ctx)

	gs.Go(func() error {
		// l, err := net.ListenTCP("tcp", test.TCPAddr(saddr))
		// require.NoError(t, err)
		// defer l.Close()

		// conn, err := l.AcceptTCP()
		// require.NoError(t, err)

		// _, err = io.Copy(conn, conn)
		// require.NoError(t, err)
		// return nil

		// test.LocIP().AsSlice()
		conn, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: []byte{127, 0, 0, 1}})
		require.NoError(t, err)
		defer conn.Close()
		// raw, err := conn.SyscallConn()
		// require.NoError(t, err)
		// err = bpf.SetRawBPF(raw, bpf.FilterPorts(caddr.Port(), saddr.Port()))
		// require.NoError(t, err)
		var b = make([]byte, 1536)
		for {
			n, err := conn.Read(b)
			require.NoError(t, err)
			iphdr := header.IPv4(b[:n])

			tcphdr := header.TCP(iphdr[iphdr.HeaderLength():])
			if tcphdr.SourcePort() == 19986 || tcphdr.DestinationPort() == 19986 {
				fmt.Printf(
					"server %s:%d-->%s:%d	%s\n",
					iphdr.SourceAddress(), tcphdr.SourcePort(),
					iphdr.DestinationAddress(), tcphdr.DestinationPort(),
					tcphdr.Flags(),
				)
			}
		}
	})
	time.Sleep(time.Second)

	gs.Go(func() error {
		raw, err := ConnectEth(caddr, saddr)
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
		return conn.Close()
	})

	fmt.Println(gs.Wait())
}
