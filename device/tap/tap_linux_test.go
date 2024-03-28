package tap_test

import (
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/rsocket/device/tap"
	"github.com/lysShub/rsocket/test"
	"github.com/stretchr/testify/require"
)

func Test_Create(t *testing.T) {
	ap, err := tap.Create("testcreate")
	require.NoError(t, err)
	defer ap.Close()

	{
		err = ap.SetAddr(netip.MustParsePrefix("10.0.3.7/24"))
		require.NoError(t, err)

		addr, err := ap.Addr()
		require.NoError(t, err)
		require.Equal(t, netip.MustParsePrefix("10.0.3.7/24"), addr)
	}

	{
		var hw = make(net.HardwareAddr, 6)
		_, err = rand.New(rand.NewSource(0)).Read(hw)
		require.NoError(t, err)
		hw[0] = 0
		err = ap.SetHardware(hw)
		require.NoError(t, err)

		new, err := ap.Hardware()
		require.NoError(t, err)
		require.Equal(t, hw.String(), new.String())
	}
}

func Test_Conn_Server(t *testing.T) {
	// addr := netip.MustParsePrefix("172.18.0.1/24")
	addr := netip.PrefixFrom(test.LocIP().Next(), 32)

	ap, err := tap.Create("tap1")
	require.NoError(t, err)
	defer ap.Close()
	err = ap.SetAddr(addr)
	require.NoError(t, err)

	var rip net.IP
	ips, err := net.LookupIP("baidu.com")
	require.NoError(t, err)
	for _, e := range ips {
		if rip = e.To4(); rip != nil {
			break
		}
	}
	if rip == nil {
		t.FailNow()
	}

	conn, err := net.DialTCP("tcp",
		&net.TCPAddr{IP: addr.Addr().AsSlice(), Port: 19986},
		&net.TCPAddr{IP: rip, Port: 80},
	)
	require.NoError(t, err)
	defer conn.Close()

	req, err := http.NewRequest("GET", "http://baidu.com", nil)
	require.NoError(t, err)
	req.Host = "baidu.com"

	resp, err := (&http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
	}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
}

func Test_Loopback(t *testing.T) {
	var (
		caddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 3, 1}), 19986)

		// caddr = netip.AddrPortFrom(test.LocIP().Next(), 19986)
		saddr = netip.AddrPortFrom(test.LocIP(), 8080)
	)

	var ret = make(chan struct{})
	go func() {
		defer func() { close(ret) }()
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: saddr.Addr().AsSlice(), Port: int(saddr.Port())})
		require.NoError(t, err)
		defer l.Close()

		conn, err := l.AcceptTCP()
		require.NoError(t, err)
		defer conn.Close()
		io.Copy(conn, conn)
	}()
	time.Sleep(time.Second)

	ap, err := tap.Create("tap1")
	require.NoError(t, err)
	defer ap.Close()
	err = ap.SetAddr(netip.PrefixFrom(caddr.Addr(), 32))
	require.NoError(t, err)

	conn, err := net.DialTCP("tcp",
		&net.TCPAddr{IP: caddr.Addr().AsSlice(), Port: 19986},
		&net.TCPAddr{IP: test.LocIP().AsSlice(), Port: 8080},
	)
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	<-ret
}
