package test

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/lysShub/sockit/route"
	"github.com/mdlayher/arp"
	"github.com/stretchr/testify/require"
)

func GetIndex(t *testing.T, addr netip.Addr) int32 {
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

func DefaultGateway() (net.HardwareAddr, error) {
	rows, err := route.GetTable()
	if err != nil {
		return nil, err
	}

	for _, e := range rows {
		if e.Next.IsValid() {
			ifi, err := net.InterfaceByIndex(int(e.Interface))
			if err != nil {
				return nil, err
			}

			c, err := arp.Dial(ifi)
			if err != nil {
				return nil, err
			}
			defer c.Close()

			hw, err := c.Resolve(e.Next) // eth0 gateway
			if err != nil {
				return nil, err
			}
			return hw, err
		}
	}
	return nil, errors.New("can't get default gateway")
}
