//go:build windows
// +build windows

package internal

import (
	"net"
	"net/netip"

	"github.com/lysShub/rsocket/internal/config"
	pkge "github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// BindLocal, forbid other process use this port
func BindLocal(laddr netip.AddrPort, usedPort bool) (windows.Handle, netip.AddrPort, error) {
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
		if err == windows.WSAEADDRINUSE && usedPort {
			return 0, laddr, nil
		}
		return windows.InvalidHandle, netip.AddrPort{}, &net.OpError{
			Op:  "bind",
			Err: err,
		}
	} else if usedPort {
		return windows.InvalidHandle, netip.AddrPort{}, config.ErrNotUsedPort(laddr.Port())
	}

	if laddr.Port() == 0 {
		rsa, err := windows.Getsockname(fd)
		if err != nil {
			return windows.InvalidHandle, netip.AddrPort{}, pkge.WithMessage(err, "getsockname")
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
