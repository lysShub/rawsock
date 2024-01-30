package tcp

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/divert-go"
	"github.com/lysShub/relraw/internal/test"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var _ = func() int {
	divert.MustLoad(divert.DLL, divert.Sys)
	return 0
}()

func Test_Create_Tuns(t *testing.T) {
	tup, err := test.CreateTunTuple()
	require.NoError(t, err)

	var (
		saddr = &net.TCPAddr{IP: tup.Addr1.AsSlice(), Port: 8080}
		caddr = &net.TCPAddr{IP: tup.Addr2.AsSlice(), Port: 19986}
	)

	go func() {
		l, err := net.ListenTCP("tcp", saddr)
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.AcceptTCP()
		require.NoError(t, err)
		go io.Copy(conn, conn)
	}()
	time.Sleep(time.Second * 2)

	conn, err := net.DialTCP("tcp", caddr, saddr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("hello world"))
	require.NoError(t, err)

	var b = make([]byte, 64)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, string(b[:n]), "hello world")
}

func Test_Connect(t *testing.T) {

	t.Run("connect/loopback_server", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
			caddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
		)
		raw, err := ConnectWithDivert(saddr, caddr)
		require.NoError(t, err)

		// send
		{
			go func() {
				_, err := net.DialTCP("tcp", test.TCPAddr(caddr), test.TCPAddr(saddr))
				require.NoError(t, err)
			}()
			go func() {
				_, err := net.DialTCP("tcp", test.TCPAddr(netip.AddrPortFrom(caddr.Addr(), test.RandPort())), test.TCPAddr(netip.AddrPortFrom(saddr.Addr(), test.RandPort())))
				require.NoError(t, err)
			}()
			go func() {
				_, err := net.DialTCP("tcp", test.TCPAddr(netip.AddrPortFrom(caddr.Addr(), test.RandPort())), test.TCPAddr(saddr))
				require.NoError(t, err)
			}()
		}

		// recv
		for i := 0; i < 2; i++ {
			var b = make([]byte, 1536)
			n, err := raw.Read(b)
			require.NoError(t, err)

			iphdr := header.IPv4(b[:n])
			tcphdr := header.TCP(iphdr.Payload())
			ok := iphdr.SourceAddress().As4() == caddr.Addr().As4() &&
				iphdr.DestinationAddress().As4() == saddr.Addr().As4() &&
				tcphdr.SourcePort() == caddr.Port() &&
				tcphdr.DestinationPort() == saddr.Port() &&
				tcphdr.Flags() == header.TCPFlagSyn

			require.True(t, ok)
		}
	})

	t.Run("connect/loopback_client", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
			caddr = netip.AddrPortFrom(test.LocIP, test.RandPort())
		)

		go func() {
			l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: saddr.Addr().AsSlice(), Port: int(saddr.Port())})
			require.NoError(t, err)
			defer l.Close()
			l.AcceptTCP()
		}()
		time.Sleep(time.Second)

		raw, err := ConnectWithDivert(caddr, saddr)
		require.NoError(t, err)
		syn := test.BuildRawTCP(t, caddr, saddr, nil)
		tcphdr := header.TCP(syn.Payload())
		tcphdr.SetFlags(uint8(header.TCPFlagSyn))
		n, err := raw.Write(tcphdr)
		require.NoError(t, err)
		require.Equal(t, len(tcphdr), n)

		{ // recv syn
			var b = make([]byte, 1536)
			n, err = raw.Read(b)
			require.NoError(t, err)
			iphdr := header.IPv4(b[:n])
			tcphdr := header.TCP(iphdr.Payload())

			ok := iphdr.SourceAddress().As4() == saddr.Addr().As4() &&
				iphdr.DestinationAddress().As4() == caddr.Addr().As4() &&
				tcphdr.SourcePort() == saddr.Port() &&
				tcphdr.DestinationPort() == caddr.Port() &&
				tcphdr.Flags().Contains(header.TCPFlagSyn)

			require.True(t, ok)
		}
	})

	t.Run("connect/nics_server", func(t *testing.T) {
		t.Skip()
	})

	t.Run("listen/nics_client", func(t *testing.T) {
		t.Skip()
	})

}

func Test_Listen(t *testing.T) {
	t.Skip("")
}

func Test_RawConn_Dial_UsrStack_PingPong(t *testing.T) {
	var (
		caddr = netip.AddrPortFrom(test.LocIP, test.RandPort()) // randPort()
		saddr = netip.AddrPortFrom(test.LocIP, test.RandPort()) // randPort()
	)

	// server
	go func() {
		addr := &net.TCPAddr{IP: saddr.Addr().AsSlice(), Port: int(saddr.Port())}
		l, err := net.ListenTCP("tcp", addr)
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
		raw, err := ConnectWithDivert(caddr, saddr)

		require.NoError(t, err)
		defer raw.Close()
		conn = test.PingPongWithUserStackClient(t, caddr.Addr(), raw)
	}

	// client
	_, err := conn.Write([]byte("hello"))
	require.NoError(t, err)

	var b = make([]byte, 1536)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, []byte("hello"), b[:n])
}
