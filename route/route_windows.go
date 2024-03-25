//go:build windows
// +build windows

package route

import (
	"net"
	"net/netip"

	"github.com/pkg/errors"
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
