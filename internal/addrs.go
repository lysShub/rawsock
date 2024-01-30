package internal

import (
	"fmt"
	"net"
	"net/netip"
)

func IsWindowLoopBack(addr netip.Addr) bool {
	if addr.IsLoopback() {
		return true
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}

	for _, a := range addrs {
		var ip net.IP
		switch a := a.(type) {
		case *net.IPAddr:
			ip = a.IP
		case *net.IPNet:
			ip = a.IP
		default:
			continue
		}

		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		if a == addr {
			return true
		} else if a.Is4In6() {
			if netip.AddrFrom4(a.As4()) == addr {
				return true
			}
		}
	}
	return false
}

func GetNICIndex(addr netip.Addr) (int, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0, err
	}

	nic := 0
	for _, i := range ifs {
		as, err := i.Addrs()
		if err != nil {
			return 0, err
		}
		for _, a := range as {
			var ip net.IP
			switch a := a.(type) {
			case *net.IPAddr:
				ip = a.IP
			case *net.IPNet:
				ip = a.IP
			default:
				return 0, fmt.Errorf("unknow address type %T", a)
			}

			if a, ok := netip.AddrFromSlice(ip); !ok {
				return 0, fmt.Errorf("invalid IP address %s", ip)
			} else {
				if a.Is4In6() {
					a = netip.AddrFrom4(a.As4())
				}
				if a == addr {
					if nic == 0 {
						nic = i.Index
					} else {
						return 0, fmt.Errorf("multiple nic have address %s", a)
					}
				}
			}
		}
	}

	if nic == 0 {
		return 0, fmt.Errorf("not found nic with %s address", addr)
	} else {
		return nic, nil
	}
}
