package tcp

import (
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
)

func bindLocal(laddr netip.AddrPort) (windows.Handle, netip.AddrPort, error) {
	var sa windows.Sockaddr
	var af int = windows.AF_INET
	if laddr.Addr().Is4() {
		sa = &windows.SockaddrInet4{Addr: laddr.Addr().As4(), Port: int(laddr.Port())}
	} else {
		sa = &windows.SockaddrInet6{Addr: laddr.Addr().As16(), Port: int(laddr.Port())}
		af = windows.AF_INET6
	}

	fd, err := windows.Socket(af, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return windows.InvalidHandle, netip.AddrPort{}, &net.OpError{
			Op:  "socket",
			Err: err,
		}
	}

	if err := windows.Bind(fd, sa); err != nil {
		return windows.InvalidHandle, netip.AddrPort{}, &net.OpError{
			Op:  "bind",
			Err: err,
		}
	}

	if laddr.Port() == 0 {
		rsa, err := windows.Getsockname(fd)
		if err != nil {
			return windows.InvalidHandle, netip.AddrPort{}, &net.OpError{
				Op:  "getsockname",
				Err: err,
			}
		}
		switch sa := rsa.(type) {
		case *windows.SockaddrInet4:
			return fd, netip.AddrPortFrom(laddr.Addr(), uint16(sa.Port)), nil
		case *windows.SockaddrInet6:
			return fd, netip.AddrPortFrom(laddr.Addr(), uint16(sa.Port)), nil
		default:
		}
	}
	return fd, laddr, nil
}
