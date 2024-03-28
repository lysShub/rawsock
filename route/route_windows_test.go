//go:build windows
// +build windows

package route_test

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/lysShub/rsocket/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func Gateway(dst netip.Addr) (gateway netip.Prefix, ifIdx int, err error) {
	var idx uint32
	if dst.Is4() {
		err = windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: dst.As4()}, &idx)
	} else {
		err = windows.GetBestInterfaceEx(&windows.SockaddrInet6{Addr: dst.As16()}, &idx)
	}
	if err != nil {
		return netip.Prefix{}, 0, errors.WithStack(err)
	}

	addrs, err := (&net.Interface{Index: int(idx)}).Addrs()
	if err != nil {
		return netip.Prefix{}, 0, errors.WithStack(err)
	}
	for _, addr := range addrs {
		if addr, ok := addr.(*net.IPNet); ok {
			ones, _ := addr.Mask.Size()
			if dst.Is4() && addr.IP.To4() != nil {
				gateway = netip.PrefixFrom(
					netip.AddrFrom4([4]byte(addr.IP.To4())),
					ones,
				)
				return gateway, int(idx), nil
			} else if dst.Is6() {
				gateway = netip.PrefixFrom(
					netip.AddrFrom16([16]byte(addr.IP)),
					ones,
				)
				return gateway, int(idx), nil
			}
		}
	}
	return netip.Prefix{}, int(idx), errors.Errorf("addapter index %d without valid address", idx)
}

// Loopback validate the address tuple is windows loopback
func Loopback(src, dst netip.Addr) bool {
	if src.IsUnspecified() {
		if addr, _, err := Gateway(dst); err != nil {
			return false
		} else {
			src = addr.Addr()
		}
	}
	return src == dst
}

func Test_Loopback(t *testing.T) {
	{
		src := netip.IPv4Unspecified()
		dst := netip.IPv4Unspecified()
		is := Loopback(src, dst)
		require.False(t, is)
	}

	{
		src := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		dst := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		is := Loopback(src, dst)
		require.True(t, is)
	}

	{
		src := test.LocIP()
		dst := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		is := Loopback(src, dst)
		require.False(t, is)
	}

	{
		src := netip.IPv4Unspecified()
		dst := test.LocIP()
		is := Loopback(src, dst)
		require.True(t, is)
	}

	{
		src := test.LocIP()
		dst := test.LocIP()
		is := Loopback(src, dst)
		require.True(t, is)
	}
}

func Test_Gatway(t *testing.T) {
	t.Run("0.0.0.0", func(t *testing.T) {
		gate, idx, err := Gateway(netip.IPv4Unspecified())
		require.NoError(t, err)
		require.Equal(t, test.LocIP(), gate.Addr())

		expIdx := getIndex(t, test.LocIP())
		require.Equal(t, expIdx, idx)
	})

	t.Run("127.0.0.1", func(t *testing.T) {
		dst := netip.AddrFrom4([4]byte{127, 0, 0, 1})

		gate, idx, err := Gateway(dst)
		require.NoError(t, err)
		require.Equal(t, 1, idx)

		require.Equal(t, dst, gate.Addr())
	})

	t.Run("baidu.com", func(t *testing.T) {
		dst := func() netip.Addr {
			ips, err := net.LookupIP("baidu.com")
			require.NoError(t, err)
			for _, ip := range ips {
				if ip.To4() != nil {
					return netip.AddrFrom4([4]byte(ip.To4()))
				}
			}
			panic("")
		}()

		gate, idx, err := Gateway(dst)
		require.NoError(t, err)
		require.Equal(t, test.LocIP(), gate.Addr())

		expIdx := getIndex(t, test.LocIP())
		require.Equal(t, expIdx, idx)
	})
}

func getIndex(t *testing.T, addr netip.Addr) int {
	ifs, err := net.Interfaces()
	require.NoError(t, err)

	for _, i := range ifs {
		addrs, err := i.Addrs()
		require.NoError(t, err)
		for _, a := range addrs {
			if a, ok := a.(*net.IPNet); ok {
				_, bits := a.Mask.Size()
				if bits == addr.BitLen() {
					if a.IP.To4() != nil {
						if netip.AddrFrom4([4]byte(a.IP.To4())) == addr {
							return i.Index
						}
					} else {
						if netip.AddrFrom16([16]byte(a.IP)) == addr {
							return i.Index
						}
					}
				}
			}
		}
	}
	t.Fatal("not found address")
	return 0
}

func Test_Loopback1(t *testing.T) {
	var suits = []struct {
		src netip.Addr
		dst netip.Addr
	}{
		{
			// src: netip.MustParseAddr("192.168.0.102"),
			// src: netip.MustParseAddr("127.0.0.1"),
			src: netip.MustParseAddr("0.0.0.0"),
			dst: netip.MustParseAddr("224.0.0.251"),
		},
	}

	for _, e := range suits {
		// ok := Loopback(e.src, e.dst)
		// require.True(t, ok)

		var idx1 uint32
		err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: e.src.As4()}, &idx1)
		require.NoError(t, err)
		ifi, err := net.InterfaceByIndex(int(idx1))
		require.NoError(t, err)
		addrs, err := ifi.Addrs()
		require.NoError(t, err)
		for _, e := range addrs {
			fmt.Println((e).String())
		}
		return

		var idx2 uint32
		err = windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: e.dst.As4()}, &idx2)
		require.NoError(t, err)
		e.dst.IsLinkLocalMulticast()

		fmt.Println(idx1, idx2)
	}

}
