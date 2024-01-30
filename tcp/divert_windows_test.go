package tcp

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lysShub/divert-go"
	"github.com/lysShub/wintun-go"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var _ = func() int {
	divert.MustLoad(divert.DLL, divert.Sys)
	return 0
}()

func toTCPAddr(a netip.AddrPort) *net.TCPAddr {
	return &net.TCPAddr{IP: a.Addr().AsSlice(), Port: int(a.Port())}
}

type tunTuple struct {
	ap1, ap2     *wintun.Adapter
	Addr1, Addr2 netip.Addr
	statue       atomic.Uint32
}

func (t *tunTuple) start() error {
	go t.srv(t.ap1, t.ap2, t.Addr2)
	go t.srv(t.ap2, t.ap1, t.Addr1)
	return nil
}

func (t *tunTuple) srv(self, peer *wintun.Adapter, peerAddr netip.Addr) {
	for t.statue.Load() == 0 {
		p, err := self.ReceivePacket()
		if err != nil {
			panic(err)
		}

		switch header.IPVersion(p) {
		case 4:
			iphdr := header.IPv4(p)
			if netip.AddrFrom4(iphdr.DestinationAddress().As4()) == peerAddr {

				// if iphdr.TransportProtocol() == header.TCPProtocolNumber {
				// 	tcphdr := header.TCP(iphdr.Payload())

				// 	data := ""
				// 	if tcphdr.Flags().Contains(header.TCPFlagPsh) {
				// 		data = string(tcphdr.Payload())
				// 	}

				// 	fmt.Printf(
				// 		"%s:%d --> %s:%d  %s\n",
				// 		iphdr.SourceAddress(), tcphdr.SourcePort(), iphdr.DestinationAddress(), tcphdr.DestinationPort(),
				// 		data,
				// 	)
				// }

				np, err := peer.AllocateSendPacket(uint32(len(p)))
				if err != nil {
					panic(err)
				}
				copy(np, p)

				if err := peer.SendPacket(np); err != nil {
					panic(err)
				}
			}
		default:
		}
		self.ReleasePacket(p)
	}
	self.Close()
	t.statue.Add(1)
}

func (t *tunTuple) Close() error {
	t.statue.Store(1)
	for t.statue.Load() != 3 {
		time.Sleep(time.Millisecond * 100)
	}
	return nil
}

// 创建两个互通的tun设备
var CreateTunTuple = func() func() (*tunTuple, error) {
	var idx atomic.Uint32

	tun, err := wintun.LoadWintun(wintun.DLL)
	if err != nil {
		panic(err)
	}

	var host = func() byte {
		for {
			h := byte(idx.Add(1))
			if byte(h) != 0 && byte(h) != 0xff {
				return byte(h)
			}
		}
	}
	const mask = 24

	return func() (*tunTuple, error) {
		var addrs = []netip.Addr{
			netip.AddrFrom4([4]byte{10, 1, 1, host()}),
			netip.AddrFrom4([4]byte{10, 1, 1, host()}),
		}

		var tt = &tunTuple{
			Addr1: addrs[0],
			Addr2: addrs[1],
		}

		for i, addr := range addrs {
			name := fmt.Sprintf("test%d", addr.As4()[3])

			ap, err := tun.CreateAdapter(name, wintun.TunType("Wintun"))
			if err != nil {
				return nil, err
			}

			luid, err := ap.GetAdapterLuid()
			if err != nil {
				return nil, err
			}
			err = luid.SetIPAddresses([]netip.Prefix{netip.PrefixFrom(addr, mask)})
			if err != nil {
				return nil, err
			}

			if i == 0 {
				tt.ap1 = ap
			} else {
				tt.ap2 = ap
			}
		}
		return tt, tt.start()
	}
}()

func Test_Create_Tuns(t *testing.T) {
	tup, err := CreateTunTuple()
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
			saddr = netip.AddrPortFrom(locIP, randPort())
			caddr = netip.AddrPortFrom(locIP, randPort())
		)
		raw, err := ConnectWithDivert(saddr, caddr)
		require.NoError(t, err)

		// send
		{
			go func() {
				_, err := net.DialTCP("tcp", toTCPAddr(caddr), toTCPAddr(saddr))
				require.NoError(t, err)
			}()
			go func() {
				_, err := net.DialTCP("tcp", toTCPAddr(netip.AddrPortFrom(caddr.Addr(), randPort())), toTCPAddr(netip.AddrPortFrom(saddr.Addr(), randPort())))
				require.NoError(t, err)
			}()
			go func() {
				_, err := net.DialTCP("tcp", toTCPAddr(netip.AddrPortFrom(caddr.Addr(), randPort())), toTCPAddr(saddr))
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
			saddr = netip.AddrPortFrom(locIP, randPort())
			caddr = netip.AddrPortFrom(locIP, randPort())
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
		syn := buildRawTCP(t, caddr, saddr, nil)
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
		caddr = netip.AddrPortFrom(locIP, 19986) // randPort()
		saddr = netip.AddrPortFrom(locIP, 8080)  // randPort()
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
		conn = pingPongWithUserStackClient(t, caddr.Addr(), raw)
	}

	// client
	_, err := conn.Write([]byte("hello"))
	require.NoError(t, err)

	var b = make([]byte, 1536)
	n, err := conn.Read(b)
	require.NoError(t, err)

	require.Equal(t, []byte("hello"), b[:n])
}
