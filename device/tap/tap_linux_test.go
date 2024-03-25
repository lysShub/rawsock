package tap_test

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/lysShub/rsocket/device/tap"
	"github.com/stretchr/testify/require"
)

func Test_Create(t *testing.T) {
	ap, err := tap.Create("test1")
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

func Test_Conn(t *testing.T) {
	t.Skip("can't test on wsl")

	addr := netip.MustParsePrefix("10.0.3.7/24")

	ap, err := tap.Create("test1")
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

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s:80", rip.String()), nil)
	require.NoError(t, err)
	req.Host = "baidu.com"

	resp, err := (&http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		Timeout: time.Second * 5,
	}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
}
