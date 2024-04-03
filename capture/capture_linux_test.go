//go:build linux
// +build linux

package capture

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/lysShub/rsocket/device/tun"
	"github.com/stretchr/testify/require"
)

func TestXxxx(t *testing.T) {

	conn, err := net.DialUDP("udp",
		&net.UDPAddr{Port: 19986},
		&net.UDPAddr{IP: net.IP{192, 168, 43, 35}, Port: 8080},
	)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("1234"))
	require.NoError(t, err)
}

func TestVvvv(t *testing.T) {
	// eth, err := helper.IoctlGifhwaddr("eth0")
	// require.NoError(t, err)
	// fmt.Println(eth)

	// addr := netip.MustParsePrefix("172.18.0.1/24")
	// addr := netip.PrefixFrom(test.LocIP().Next(), 32)

	var eth = []byte{
		0x00, 0x15, 0x5d, 0x1a, 0xd4, 0xe6, 0x00, 0x15, 0x5d, 0x96, 0x3e, 0xaf, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x20, 0x01, 0xa4, 0x40, 0x00, 0x40, 0x11, 0x1e, 0x2b, 0xac, 0x18, 0x83, 0x1a, 0xc0, 0xa8,
		0x2b, 0x23, 0x4e, 0x12, 0x1f, 0x90, 0x00, 0x0c, 0x1b, 0x1c, 0x31, 0x32, 0x33, 0x34,
	}

	addr := netip.PrefixFrom(
		netip.AddrFrom4([4]byte{10, 0, 0, 1}), 24,
	)

	ap, err := tun.Tap("tap1")
	// ap, err := tun.Tun("tun1")
	require.NoError(t, err)
	defer ap.Close()
	err = ap.SetAddr(addr)
	require.NoError(t, err)

	n, err := ap.Write(context.Background(), eth)
	fmt.Println(n, err)
}
