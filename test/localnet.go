package test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func GetIfidx(t *testing.T, addr netip.Addr) int32 {
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
							return int32(i.Index)
						}
					} else {
						if netip.AddrFrom16([16]byte(a.IP)) == addr {
							return int32(i.Index)
						}
					}
				}
			}
		}
	}
	t.Fatal("not found address")
	return 0
}

func LocIP() netip.Addr {
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: []byte{8, 8, 8, 8}, Port: 53})
	if err != nil {
		panic(err)
	}
	defer c.Close()
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}

func Baidu() netip.Addr {
	ips, err := net.LookupIP("baidu.com")
	if err != nil {
		panic(err)
	}

	for _, e := range ips {
		if ip := e.To4(); ip != nil {
			return netip.AddrFrom4([4]byte(ip))
		}
	}
	panic("not found ")
}
